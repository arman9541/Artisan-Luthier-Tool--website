require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set in production!");
}
if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_PUBLISHABLE_KEY) {
  throw new Error("Stripe keys must be set in environment variables!");
}

const app = express();

// Trust first proxy (for Render or Heroku)
app.set('trust proxy', 1);

// SECURITY: Enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      return res.redirect(`https://${req.header('host')}${req.url}`);
    }
    next();
  });
}

// SECURITY: Add headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com"],
      frameSrc: ["https://js.stripe.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com"]
    }
  }
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, try later.'
});
const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many checkout attempts, try later.'
});

app.use('/create-checkout-session', checkoutLimiter);
app.use(generalLimiter);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// SESSION: MongoDB store recommended for production
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
  mongoUrl: process.env.MONGO_URI,
  collectionName: 'sessions'
}), 
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// CSRF protection
const csrfProtection = csrf({ cookie: true });

// ---------------- STRIPE WEBHOOK ----------------
// Must come BEFORE express.json() middleware
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const sessionObj = event.data.object;
      console.log('Payment successful:', sessionObj.id);
      // Optional: clear cart in DB/session store using sessionObj.metadata.sessionId
      // Optional: send confirmation email, store order in DB
      break;
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
});

// ---------------- PARSERS ----------------
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ---------------- EJS ----------------
app.set('view engine', 'ejs');

// ---------------- PRODUCTS ----------------
const PRODUCTS = {
  'cello-neck-adjusting': { name: "Cello Neck Setting Adjusting Tool", price: 420, description: "Ensures optimal neck angle alignment for cellos." },
  'cello-neck-fixing': { name: "Cello Neck Fixing Tool", price: 350, description: "Securely holds the cello fingerboard and neck in place." },
  'violin-neck-adjusting': { name: "Violin/Viola Neck Setting Adjusting Tool", price: 370, description: "Ensures optimal neck angle alignment for violin/viola." },
  'violin-neck-fixing': { name: "Violin/Viola Neck Fixing Tool", price: 285, description: "Securely holds the violin/viola fingerboard and neck in place." },
  'violin-fhole-jack': { name: "Special Design Violin f-hole Leveling Jack", price: 80, description: "Precisely align surface cracks on the violin f-holes." },
  'cello-fhole-jack': { name: "Special Design Cello f-hole leveling jack", price: 100, description: "Precisely align surface cracks on the cello f-holes." },
  'cello-fhole-clamp': { name: "Special Design Cello f-hole crack clamp", price: 380, description: "Aligns and stabilizes cello top cracks at the f-hole." },
  'violin-fhole-clamp': { name: "Special Design Violin/Viola f-hole crack clamp", price: 320, description: "Aligns and stabilizes violin or viola top cracks at the f-hole." },
  'violin-clamps-35': { name: "35 pcs Violin/Viola Clamps", price: 495, description: "Color-coded clamps to protect varnish and edges during gluing." },
  'cello-clamps-45': { name: "45 pcs Cello clamps", price: 690, description: "Color-coded clamps to protect varnish and edges during gluing." }
};

// ---------------- ROUTES ----------------
app.get('/', (req, res) => res.render('index'));

app.get('/config', csrfProtection, (req, res) => {
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    csrfToken: req.csrfToken()
  });
});

function validateCartItem(item) {
  return item && typeof item === 'object' &&
         typeof item.productId === 'string' &&
         typeof item.qty === 'number' && item.qty > 0 && item.qty <= 99 &&
         PRODUCTS[item.productId];
}

// Add to cart
app.post('/api/cart/add', csrfProtection, (req, res) => {
  try {
    const { productId, qty } = req.body;
    const quantity = Number(qty);

    if (!validateCartItem({ productId, qty: quantity })) {
      return res.status(400).json({ error: 'Invalid product or quantity' });
    }

    if (!req.session.cart) req.session.cart = {};
    const newQty = (req.session.cart[productId] || 0) + quantity;

    if (newQty > 99) return res.status(400).json({ error: 'Maximum quantity exceeded' });

    req.session.cart[productId] = newQty;
    res.json({ success: true, cart: req.session.cart });
  } catch (err) {
    console.error('Cart add error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get cart
app.get('/api/cart', (req, res) => {
  const cart = req.session.cart || {};
  const cartItems = Object.entries(cart).map(([productId, qty]) => ({
    ...PRODUCTS[productId],
    productId,
    qty
  }));
  res.json({ cart: cartItems });
});

// Create checkout session
app.post('/create-checkout-session', csrfProtection, async (req, res) => {
  try {
    const cart = req.session.cart;
    if (!cart || Object.keys(cart).length === 0) return res.status(400).json({ error: 'Cart is empty' });

    const line_items = Object.entries(cart).map(([productId, qty]) => {
      const product = PRODUCTS[productId];
      if (!product) throw new Error('Invalid product in cart');
      if (typeof qty !== 'number' || qty < 1 || qty > 99) throw new Error('Invalid quantity');

      return {
        price_data: {
          currency: 'usd',
          product_data: { name: product.name, description: product.description },
          unit_amount: Math.round(product.price * 100)
        },
        quantity: qty
      };
    });

    const sessionObj = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: `${process.env.BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancel.html`,
      metadata: { sessionId: req.sessionID }
    });

    res.json({ id: sessionObj.id });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Unable to create checkout session' });
  }
});

// Success / Cancel pages
app.get('/success.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

app.get('/cancel.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cancel.html'));
});

// 404 handler
app.use((req, res) => res.status(404).send('Page not found'));

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔒 Secure server running on port ${PORT}`));
