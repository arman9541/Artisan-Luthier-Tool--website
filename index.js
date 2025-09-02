require('dotenv').config();
const express = require('express');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();

// EJS setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname))); // serve products.html, images, css, etc.

// Routes
app.get("/products", (req, res) => {
  res.sendFile(path.join(__dirname, "products.html"));
});

app.get("/checkout", (req, res) => {
  res.render("index"); // renders views/index.ejs
});

app.post('/checkout', async (req, res) => {
  try {
    const cart = JSON.parse(req.body.cart || "[]");

    if (!cart.length) {
      return res.redirect("/checkout"); // no items, back to checkout page
    }

    // Convert cart to Stripe line items
    const line_items = cart.map(item => ({
      price_data: {
        currency: 'usd',
        product_data: { name: item.name },
        unit_amount: Math.round(item.price * 100), // Stripe needs cents
      },
      quantity: item.qty,
    }));

    const session = await stripe.checkout.sessions.create({
      line_items,
      mode: 'payment',
      shipping_address_collection: {
        allowed_countries: ['US', 'CA', 'TR', 'MX', 'IT', 'DE', 'ES', 'FR'],
      },
      success_url: `${process.env.BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancel`,
    });

    res.redirect(session.url);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error creating Stripe Checkout session");
  }
});

app.get('/success', async (req, res) => {
  try {
    const result = await Promise.all([
      stripe.checkout.sessions.retrieve(req.query.session_id, { expand: ['payment_intent.payment_method'] }),
      stripe.checkout.sessions.listLineItems(req.query.session_id),
    ]);

    console.log(JSON.stringify(result, null, 2));
    res.render("success", { session: result[0], items: result[1].data });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error retrieving session");
  }
});

app.get('/cancel', (req, res) => {
  res.redirect('/checkout');
});

app.use(express.static(path.join(__dirname)));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on http://localhost:${PORT}`));
