console.log('--- SERVER STARTED WITH MOBILE OPTIMIZATIONS index.js ---');

require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');

// ===== ENV CHECK =====
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET must be set!");
if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_PUBLISHABLE_KEY)
  throw new Error("Stripe keys must be set!");
if (!process.env.BASE_URL) throw new Error("BASE_URL must be set!");
if (!process.env.STRIPE_WEBHOOK_SECRET)
  throw new Error("STRIPE_WEBHOOK_SECRET must be set!");

const BASE_URL = process.env.BASE_URL.trim().replace(/\/+$/, '');
const app = express();
const isProd = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);


// =====================================================
// DUPLICATE EVENT STORE (ANTI-RETRY PROTECTION)
// =====================================================
const processedEvents = new Set();


// =====================================================
// SESSION-TO-CART MAPPING (FOR WEBHOOK CART CLEARING)
// =====================================================
// Maps Express session IDs to cart data
// This allows the webhook to clear carts after successful payment
const sessionCarts = new Map();

// Clean up old sessions every hour (prevents memory leak)
setInterval(() => {
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  for (const [sessionId, data] of sessionCarts.entries()) {
    if (data.timestamp < oneHourAgo) {
      sessionCarts.delete(sessionId);
      console.log('[CLEANUP] Removed old session cart:', sessionId);
    }
  }
}, 60 * 60 * 1000);


// ===== CORS =====
app.use(cors({
  origin: (origin, callback) => {
    const allowed = [
      'https://artisanluthiertools.com',
      'https://www.artisanluthiertools.com',
      'https://api.artisanluthiertools.com'
    ];
    if (!origin || !isProd || allowed.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));


// ===== SECURITY HEADERS =====
app.use(helmet());


// ===== RATE LIMIT =====
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
const checkoutLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });


// =====================================================
// STRIPE WEBHOOK RAW BODY (MUST BE BEFORE JSON PARSER)
// =====================================================
app.post('/webhook', express.raw({ type: 'application/json' }));


// ===== BODY PARSERS =====
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());


// ===== SESSIONS =====
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'artisan_session',
  proxy: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    domain: '.artisanluthiertools.com',
    maxAge: 24 * 60 * 60 * 1000
  }
}));


// =====================================================
// NO CACHE HEADERS
// =====================================================
app.use(['/api/cart', '/create-checkout-session'], (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});


// ===== CSRF =====
app.use(csrf({
  value: req =>
    req.headers['csrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.body._csrf ||
    req.query._csrf,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
}));


// =====================================================
// SESSION INIT ROUTE (iOS FIX)
// =====================================================
app.get('/init-session', (req, res) => {
  console.log('[SESSION-INIT] Initializing session...');
  req.session.initialized = true;
  req.session.save(err => {
    if (err) {
      console.error('[SESSION-INIT] Error:', err);
      return res.status(500).json({ error: 'Session initialization failed' });
    }
    console.log('[SESSION-INIT] Success. Session ID:', req.sessionID);
    res.json({ success: true, sessionId: req.sessionID });
  });
});


// ======= PRODUCTS DATA =======
const PRODUCTS = {
  'cello-neck-adjusting': { name: "Cello Neck Setting Adjusting Tool", price: 420, description: "Ensures optimal neck angle alignment for cellos." },
  'cello-neck-fixing': { name: "Cello Neck Fixing Tool", price: 350, description: "Securely holds the cello fingerboard and neck in place." },
  'violin-neck-adjusting': { name: "Violin/Viola Neck Setting Adjusting Tool", price: 370, description: "Ensures optimal neck angle alignment for violin/viola." },
  'violin-neck-fixing': { name: "Violin/Viola Neck Fixing Tool", price: 285, description: "Securely holds the violin/viola fingerboard and neck in place." },
  'violin-fhole-jack': { name: "Special Design Violin f-hole Leveling Jack", price: 80, description: "Precisely align cracks on violin f-holes." },
  'cello-fhole-jack': { name: "Special Design Cello f-hole leveling jack", price: 100, description: "Precisely align cracks on cello f-holes." },
  'cello-fhole-clamp': { name: "Special Design Cello f-hole crack clamp", price: 380, description: "Stabilizes cello top cracks." },
  'violin-fhole-clamp': { name: "Special Design Violin/Viola f-hole crack clamp", price: 320, description: "Stabilizes violin/viola top cracks." },
  'violin-clamps-35': { name: "35 pcs Violin/Viola Clamps", price: 495, description: "Protect varnish during gluing." },
  'cello-clamps-45': { name: "45 pcs Cello clamps", price: 690, description: "Protect varnish during gluing." },  
  'popot-rouge': { name: "Popot Rouge", price: 20, description: "Specialized cleaner for rare instruments. Removes dirt, rosin, and fingerprints. Nourishes varnish and maintains natural shine. Proven safe for antique Italian instruments." }
};


// ===== CONFIG =====
app.get('/config', (req, res) => {
  if (!req.session.initialized) req.session.initialized = true;
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    csrfToken: req.csrfToken()
  });
});


// ===== CART ROUTES =====
app.post('/api/cart/add', (req, res) => {
  const { productId, qty } = req.body;
  if (!PRODUCTS[productId]) return res.status(400).json({ error: 'Invalid product' });

  if (!req.session.cart) req.session.cart = {};
  req.session.cart[productId] = (req.session.cart[productId] || 0) + Number(qty);

  res.json({ success: true, cart: req.session.cart });
});

app.get('/api/cart', (req, res) => {
  res.json({ cart: req.session.cart || {} });
});

app.post('/api/cart/clear', (req, res) => {
  console.log('[CART CLEAR] Clearing cart for session:', req.sessionID);
  req.session.cart = {};
  req.session.save(err => {
    if (err) {
      console.error('[CART CLEAR ERROR]', err);
      return res.status(500).json({ error: 'Failed to clear cart' });
    }
    console.log('[CART CLEAR] Cart cleared successfully');
    res.json({ success: true });
  });
});


// ===== CHECKOUT =====
app.post('/create-checkout-session', checkoutLimiter, async (req, res) => {
  try {
    const cart = req.session.cart;
    if (!cart || !Object.keys(cart).length)
      return res.status(400).json({ error: 'Cart empty' });

    const line_items = Object.entries(cart).map(([id, qty]) => ({
      price_data: {
        currency: 'usd',
        product_data: { name: PRODUCTS[id].name },
        unit_amount: PRODUCTS[id].price * 100
      },
      quantity: qty
    }));

    // Store session cart mapping for webhook to clear later
    sessionCarts.set(req.sessionID, {
      cart: { ...cart },
      timestamp: Date.now()
    });

    const sessionObj = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: `${BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/cancel.html`,
      metadata: {
        expressSessionId: req.sessionID
      }
    });

    console.log('[CHECKOUT] Created session for:', req.sessionID);
    res.json({ id: sessionObj.id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Stripe session failed' });
  }
});


// =====================================================
// WEBHOOK HANDLER WITH DUPLICATE PROTECTION & CART CLEARING
// =====================================================
app.post('/webhook', async (req, res) => {

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ===== DUPLICATE CHECK =====
  if (processedEvents.has(event.id)) {
    console.log('[WEBHOOK] Duplicate ignored:', event.id);
    return res.json({ received: true });
  }

  processedEvents.add(event.id);

  console.log('[WEBHOOK EVENT]', event.type);

  try {

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      console.log('[PAYMENT SUCCESS]', session.id);

      // ===== CLEAR CART AFTER SUCCESSFUL PAYMENT =====
      const expressSessionId = session.metadata?.expressSessionId;
      
      if (expressSessionId && sessionCarts.has(expressSessionId)) {
        console.log('[CART CLEAR] Clearing cart for session:', expressSessionId);
        sessionCarts.delete(expressSessionId);
        console.log('[CART CLEAR] Cart cleared successfully');
      } else {
        console.warn('[CART CLEAR] No session found for:', expressSessionId);
      }

      // future:
      // send email confirmation
      // save order to database
      // trigger fulfillment
    }

  } catch (err) {
    console.error('[WEBHOOK PROCESS ERROR]', err);
    return res.status(500).send("Webhook handler failed");
  }

  res.json({ received: true });
});


// ===== STATIC =====
app.use(express.static(path.join(__dirname, 'public')));


// ===== SPA FALLBACK =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN')
    return res.status(403).json({ error: 'Invalid CSRF token' });

  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});


// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));