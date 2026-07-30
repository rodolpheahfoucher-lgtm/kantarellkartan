// This file becomes a live webhook automatically once it's in your GitHub
// repo's /api folder and Vercel redeploys — no extra setup needed on
// Vercel's side beyond adding the Environment Variables listed below.
//
// Its web address will be:
//   https://kantarelljakten.se/api/stripe-webhook
//
// Required Environment Variables (set these in Vercel: your project →
// Settings → Environment Variables):
//   STRIPE_WEBHOOK_SECRET   - from Stripe → Developers → Webhooks → your endpoint (starts with whsec_)
//   CODE_SECRET             - must exactly match the CODE_SECRET in index.html
//   RESEND_API_KEY          - from resend.com → API Keys
//   FROM_EMAIL              - e.g. "Kantarelljakten <onboarding@resend.dev>"

export const config = { runtime: 'edge' };

export default async function handler(request) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const payload = await request.text();
  const sigHeader = request.headers.get('stripe-signature');

  let event;
  try {
    event = await verifyStripeSignature(payload, sigHeader, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return new Response(`Webhook signature verification failed: ${err.message}`, { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email;
    const sessionId = session.id;

    if (email) {
      const code = await generateCode(sessionId, process.env.CODE_SECRET);
      try {
        await sendEmail(email, code);
      } catch (err) {
        console.error('Email send failed:', err.message);
        // We still return 200 below so Stripe doesn't keep retrying just
        // because the email provider hiccuped.
      }
    } else {
      console.error('No customer email on session', sessionId);
    }
  }

  return new Response(JSON.stringify({ status: 'ok' }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ---- Stripe signature verification -----------------------------------

async function verifyStripeSignature(payload, sigHeader, secret) {
  if (!sigHeader) throw new Error('missing stripe-signature header');

  const parts = Object.fromEntries(sigHeader.split(',').map((p) => p.split('=')));
  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) throw new Error('malformed signature header');

  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const macBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const expected = [...new Uint8Array(macBuffer)].map((b) => b.toString(16).padStart(2, '0')).join('');

  if (expected !== signature) throw new Error('signature mismatch');

  return JSON.parse(payload);
}

// ---- Code generation (must mirror isValidGeneratedCode in index.html) ----

async function generateCode(sessionId, secret) {
  const suffix = sessionId.replace(/[^a-zA-Z0-9]/g, '').slice(-6).toUpperCase();
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const macBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(suffix));
  const macArray = [...new Uint8Array(macBuffer)];
  const checksum = macArray.map((b) => b.toString(36)).join('').toUpperCase().slice(0, 4);
  return `KANTA-${suffix}-${checksum}`;
}

// ---- Email via Resend ---------------------------------------------------

async function sendEmail(to, code) {
  const html = `
    <div style="font-family:sans-serif;color:#1a2410;max-width:480px;margin:0 auto;">
      <h2 style="color:#2d4a1e;">Tack för ditt köp! 🍄</h2>
      <p>Här är din premiumkod för Kantarelljakten:</p>
      <p style="font-size:22px;font-weight:bold;background:#f5e4b0;color:#2d4a1e;
                padding:14px 20px;border-radius:8px;display:inline-block;letter-spacing:1px;">
        ${code}
      </p>
      <p>Öppna appen, tryck på "Prenumerera" och skriv in koden under
         "Har du redan en kod?" längst ner i rutan.</p>
      <p>Lycka till i skogen!<br>/ Kantarelljakten</p>
    </div>
  `;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.FROM_EMAIL,
      to,
      subject: 'Din Kantarelljakten Premium-kod 🍄',
      html,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend API error ${res.status}: ${body}`);
  }
}
