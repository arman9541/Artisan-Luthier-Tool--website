let cart = JSON.parse(localStorage.getItem('cart') || '[]');

function updateCartCount() {
  const count = cart.reduce((sum, item) => sum + item.qty, 0);
  const cartCountEl = document.getElementById('cart-count');
  if (cartCountEl) cartCountEl.textContent = count;
}

window.addEventListener('storage', () => {
  cart = JSON.parse(localStorage.getItem('cart') || '[]');
  updateCartCount();
});

updateCartCount();

