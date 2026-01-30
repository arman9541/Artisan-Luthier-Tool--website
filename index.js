index.js
require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const app = express();

// SECURITY: Enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// SECURITY: Add security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "https://js.stripe.com"],
      frameSrc: ["https://js.stripe.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com"]
    }
  }
}));

// SECURITY: Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Only 10 checkout attempts per 15 minutes
  message: 'Too many checkout attempts, please try again later.'
});

app.use('/create-checkout-session', checkoutLimiter);
app.use(limiter);

// SECURITY: Request size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// SECURITY: Session management (server-side cart storage)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict' // CSRF protection
  }
}));

// SECURITY: CSRF Protection
const csrfProtection = csrf({ cookie: true });

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS
app.set('view engine', 'ejs');

// SECURITY: Product catalog stored SERVER-SIDE (not client-side)
const PRODUCTS = {
  'cello-neck-adjusting': { 
    name: "Cello Neck Setting Adjusting Tool", 
    price: 420,
    description: "Ensures optimal neck angle alignment for cellos."
  },
  'cello-neck-fixing': { 
    name: "Cello Neck Fixing Tool", 
    price: 350,
    description: "Securely holds the cello fingerboard and neck in place."
  },
  'violin-neck-adjusting': { 
    name: "Violin/Viola Neck Setting Adjusting Tool", 
    price: 370,
    description: "Ensures optimal neck angle alignment for violin/viola."
  },
  'violin-neck-fixing': { 
    name: "Violin/Viola Neck Fixing Tool", 
    price: 285,
    description: "Securely holds the violin/viola fingerboard and neck in place."
  },
  'violin-fhole-jack': { 
    name: "Special Design Violin f-hole Leveling Jack", 
    price: 80,
    description: "Precisely align surface cracks on the violin f-holes."
  },
  'cello-fhole-jack': { 
    name: "Special Design Cello f-hole leveling jack", 
    price: 100,
    description: "Precisely align surface cracks on the cello f-holes."
  },
  'cello-fhole-clamp': { 
    name: "Special Design Cello f-hole crack clamp", 
    price: 380,
    description: "Aligns and stabilizes cello top cracks at the f-hole."
  },
  'violin-fhole-clamp': { 
    name: "Special Design Violin/Viola f-hole crack clamp", 
    price: 320,
    description: "Aligns and stabilizes violin or viola top cracks at the f-hole."
  },
  'violin-clamps-35': { 
    name: "35 pcs Violin/Viola Clamps", 
    price: 495,
    description: "Color-coded clamps to protect varnish and edges during gluing."
  },
  'cello-clamps-45': { 
    name: "45 pcs Cello clamps", 
    price: 690,
    description: "Color-coded clamps to protect varnish and edges during gluing."
  }
};

// Render index
app.get('/', (req, res) => {
  res.render('index');
});

// SECURITY: Return config with CSRF token
app.get('/config', csrfProtection, (req, res) => {
  res.json({ 
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    csrfToken: req.csrfToken()
  });
});

// SECURITY: Input validation helper
function validateCartItem(item) {
  if (!item || typeof item !== 'object') return false;
  if (!item.productId || typeof item.productId !== 'string') return false;
  if (!item.qty || typeof item.qty !== 'number' || item.qty < 1 || item.qty > 99) return false;
  if (!PRODUCTS[item.productId]) return false;
  return true;
}

// SECURITY: Server-side cart management
app.post('/api/cart/add', csrfProtection, (req, res) => {
  try {
    const { productId, qty } = req.body;
    
    // Validate input
    if (!validateCartItem({ productId, qty: parseInt(qty) })) {
      return res.status(400).json({ error: 'Invalid product or quantity' });
    }

    // Initialize cart if needed
    if (!req.session.cart) {
      req.session.cart = {};
    }

    // Add to server-side cart
    const currentQty = req.session.cart[productId] || 0;
    const newQty = currentQty + parseInt(qty);
    
    if (newQty > 99) {
      return res.status(400).json({ error: 'Maximum quantity exceeded' });
    }

    req.session.cart[productId] = newQty;

    res.json({ 
      success: true, 
      cart: req.session.cart 
    });
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

// SECURITY: Create checkout session with server-side validation
app.post('/create-checkout-session', csrfProtection, async (req, res) => {
  try {
    const cart = req.session.cart;

    // SECURITY: Validate cart exists and is not empty
    if (!cart || Object.keys(cart).length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    // SECURITY: Build line items from SERVER-SIDE product data
    // This prevents price manipulation from client
    const line_items = Object.entries(cart).map(([productId, qty]) => {
      const product = PRODUCTS[productId];
      
      // Double-check product exists
      if (!product) {
        throw new Error('Invalid product in cart');
      }

      // Validate quantity
      if (typeof qty !== 'number' || qty < 1 || qty > 99) {
        throw new Error('Invalid quantity');
      }

      return {
        price_data: {
          currency: 'usd',
          product_data: { 
            name: product.name,
            description: product.description 
          },
          unit_amount: Math.round(product.price * 100), // SERVER-SIDE PRICE
        },
        quantity: qty,
      };
    });

    // Create Stripe session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: `${process.env.BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancel.html`,
      metadata: {
        // Store any order metadata here
        sessionId: req.sessionID
      }
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error('Checkout error:', err);
    // SECURITY: Don't expose internal error details
    res.status(500).json({ error: 'Unable to create checkout session' });
  }
});

// SECURITY: Stripe webhook for payment verification
app.post('/webhook', 
  express.raw({ type: 'application/json' }), 
  async (req, res) => {
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

    // Handle the event
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        console.log('Payment successful:', session.id);
        // TODO: Fulfill the order, send confirmation email, etc.
        break;
      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    res.json({ received: true });
});

// Success/cancel pages
app.get('/success.html', (req, res) => {
  // Clear cart after successful payment
  req.session.cart = {};
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Payment Successful</title>
      <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        h1 { color: #4CAF50; }
      </style>
    </head>
    <body>
      <h1>✓ Payment Successful!</h1>
      <p>Thank you for your order. You will receive a confirmation email shortly.</p>
      <a href="/">Return to Home</a>
    </body>
    </html>
  `);
});

app.get('/cancel.html', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Payment Canceled</title>
      <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        h1 { color: #f44336; }
      </style>
    </head>
    <body>
      <h1>Payment Canceled</h1>
      <p>Your order was not completed.</p>
      <a href="/products.html">Return to Products</a>
    </body>
    </html>
  `);
});

// SECURITY: 404 handler
app.use((req, res) => {
  res.status(404).send('Page not found');
});

// SECURITY: Error handler (don't expose stack traces)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔒 Secure server running on port ${PORT}`));
