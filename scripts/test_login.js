// scripts/test_login.js
// Small script to POST /api/login and print the response
const fetch = global.fetch || require('node-fetch');

async function test() {
  try {
    const res = await fetch('http://localhost:3000/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'pedro@email.com', password: 'senha123' })
    });

    const text = await res.text();
    console.log('Status:', res.status);
    try { console.log('Body (parsed):', JSON.parse(text)); } catch (e) { console.log('Body (raw):', text); }
  } catch (e) {
    console.error('Request failed:', e);
  }
}

test();
