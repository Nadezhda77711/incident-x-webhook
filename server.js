const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 10000;

// Optional (для CRC и подписи, если используешь X webhooks)
const X_WEBHOOK_CONSUMER_SECRET = process.env.X_WEBHOOK_CONSUMER_SECRET || '';

// Куда слать алерты
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';

function hmacSha256Base64(input, secret) {
  return crypto.createHmac('sha256', secret).update(input).digest('base64');
}

// Health
app.get('/', (_req, res) => {
  res.status(200).send('ok');
});

// CRC endpoint (GET /x-webhook?crc_token=...)
app.get('/x-webhook', (req, res) => {
  const crcToken = req.query.crc_token;
  if (!crcToken) return res.status(200).send('ok');

  if (!X_WEBHOOK_CONSUMER_SECRET) {
    return res.status(500).json({ error: 'X_WEBHOOK_CONSUMER_SECRET is not set' });
  }

  const responseToken = 'sha256=' + hmacSha256Base64(crcToken, X_WEBHOOK_CONSUMER_SECRET);
  return res.status(200).json({ response_token: responseToken });
});

// POST webhook events
app.post('/x-webhook', async (req, res) => {
  try {
    const payload = req.body || {};
    console.log('[x-webhook] event keys:', Object.keys(payload));

    // Можно добавить строгую валидацию подписи здесь при необходимости.
    // Например, сравнивать заголовок x-twitter-webhooks-signature.

    await notifyTelegram(payload);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('[x-webhook] error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

async function notifyTelegram(payload) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;

  const text = formatAlert(payload);
  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text,
      disable_web_page_preview: true
    })
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Telegram send failed: ${resp.status} ${body}`);
  }
}

function formatAlert(payload) {
  const compact = JSON.stringify(payload).slice(0, 3000);
  return `X webhook event received\n\n${compact}`;
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
