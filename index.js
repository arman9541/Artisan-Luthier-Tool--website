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

// ======= ENV CHECK =======
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET must be set!");
if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_PUBLISHABLE_KEY)
  throw new Error("Stripe keys must be set!");
if (!process.env.BASE_URL) throw new Error("BASE_URL must be set for success/cancel URLs");

const TRUSTED_ORIGINS = process.env.CSRF_TRUSTED_ORIGINS
  ? process.env.CSRF_TRUSTED_ORIGINS.split(',').map(o => o.trim())
  : [];

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://arman9541.github.io";
const BASE_URL = process.env.BASE_URL.trim().replace(/\/+$/, '');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// ======= TRUST PROXY FOR MOBILE =======
app.set('trust proxy', 1);


// ======= CORS =======
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://artisanluthiertools.com',
      'https://www.artisanluthiertools.com',
      'https://api.artisanluthiertools.com'
    ];
    
    if (!origin) return callback(null, true);
    if (!isProd) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'csrf-token', 'x-csrf-token', 'CSRF-Token', 'X-Requested-With'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// ... keep existing code until session section ...



// ======= SECURITY HEADERS =======
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com"],
      frameSrc: ["https://js.stripe.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://artisanluthiertools.com",
        "https://api.artisanluthiertools.com"  // Added your API subdomain
      ]
    }
  }
}));

// ======= RATE LIMIT =======
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
const checkoutLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// ======= PARSERS =======
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());


// ======= SESSIONS (Enhanced for Same-Site with Subdomain) =======
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'artisan_session',
  proxy: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',  // Changed from 'none' - now we're same-site!
    domain: '.artisanluthiertools.com',  // Share cookie across subdomains
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ======= CSRF WITH iOS FIX =======
app.use(csrf({
  value: req => {
    return req.headers['csrf-token'] || 
           req.headers['CSRF-Token'] || 
           req.headers['x-csrf-token'] ||
           req.body._csrf || 
           req.query._csrf;
  },
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  cookie: false  // Use session instead of separate cookie
}));

// ======= CSRF DEBUG MIDDLEWARE =======
app.use((req, res, next) => {
  console.log('--- CSRF DEBUG ---');
  console.log('Method:', req.method);
  console.log('Path:', req.path);
  console.log('Origin:', req.headers.origin);
  console.log('Session ID:', req.sessionID);
  console.log('Session Initialized:', req.session.initialized);
  console.log('Cookies Received:', req.cookies ? 'Yes' : 'No');
  console.log('CSRF Token in Header:', req.headers['csrf-token'] ? 'Present' : 'Missing');
  next();
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
  'cello-clamps-45': { name: "45 pcs Cello clamps", price: 690, description: "Protect varnish during gluing." }  
};

// ======= NO-CACHE HEADERS FOR CART & CHECKOUT =======
app.use(['/api/cart', '/create-checkout-session'], (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ======= SESSION INITIALIZATION (NEW - iOS FIX) =======
app.get('/init-session', (req, res) => {
  console.log('[SESSION-INIT] Initializing session...');
  req.session.initialized = true;
  req.session.save((err) => {
    if (err) {
      console.error('[SESSION-INIT] Error:', err);
      return res.status(500).json({ error: 'Session initialization failed' });
    }
    console.log('[SESSION-INIT] Success. Session ID:', req.sessionID);
    res.json({ success: true, sessionId: req.sessionID });
  });
});

// ======= ROUTES =======
app.get('/config', (req, res) => {
  console.log('[CONFIG] Generating CSRF token...');
  if (!req.session.initialized) {
    req.session.initialized = true;
  }
  const token = req.csrfToken();
  console.log('[CONFIG] Token generated:', token.substring(0, 10) + '...');
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    csrfToken: token
  });
});

app.post('/api/cart/add', (req, res) => {
  const { productId, qty } = req.body;
  console.log('[CART-ADD] Product:', productId, 'Qty:', qty);
  if (!PRODUCTS[productId]) return res.status(400).json({ error: 'Invalid product' });
  if (!req.session.cart) req.session.cart = {};
  req.session.cart[productId] = (req.session.cart[productId] || 0) + Number(qty);
  console.log('[CART-ADD] Cart updated:', req.session.cart);
  res.json({ success: true, cart: req.session.cart });
});

app.post('/api/cart/remove', (req, res) => {
  const { productId } = req.body;
  if (req.session.cart && req.session.cart[productId]) {
    req.session.cart[productId] -= 1;
    if (req.session.cart[productId] <= 0) delete req.session.cart[productId];
    return res.json({ success: true, cart: req.session.cart });
  }
  res.status(400).json({ error: 'Item not in cart' });
});

app.post('/api/cart/clear', (req, res) => {
  req.session.cart = {};
  console.log('[CART] Cart cleared by user');
  res.json({ success: true, cart: {} });
});

app.get('/api/cart', (req, res) => {
  const cart = req.session.cart || {};
  const items = Object.entries(cart).map(([id, qty]) => ({
    ...PRODUCTS[id],
    productId: id,
    qty
  }));
  res.json({ cart: items });
});

app.post('/create-checkout-session', checkoutLimiter, async (req, res) => {
  try {
    const cart = req.session.cart;
    if (!cart || Object.keys(cart).length === 0) return res.status(400).json({ error: 'Cart empty' });

    const line_items = Object.entries(cart).map(([id, qty]) => {
      const product = PRODUCTS[id];
      return {
        price_data: {
          currency: 'usd',
          product_data: { name: product.name, description: product.description },
          unit_amount: Math.round(Number(product.price) * 100),
        },
        quantity: Number(qty)
      };
    });

    const sessionObj = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      billing_address_collection: 'required',
      success_url: `${BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/cancel.html`
    });

    res.json({ id: sessionObj.id });
  } catch (err) {
    console.error('[CHECKOUT] Error:', err);
    res.status(500).json({ error: 'Stripe session failed', details: err.message });
  }
});

// ======= STATIC FILES =======
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// ======= CATCH-ALL FOR SPA =======
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ======= ERROR HANDLER =======
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.error('[CSRF-ERROR] Invalid token. Session ID:', req.sessionID);
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  console.error('[ERROR]', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ======= START SERVER =======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));