const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

// Секрет из X App (API Secret Key / Consumer Secret)
const X_WEBHOOK_CONSUMER_SECRET = process.env.X_WEBHOOK_CONSUMER_SECRET || "";

// Telegram
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";

function hmacSha256Base64(input, secret) {
  return crypto.createHmac("sha256", secret).update(input).digest("base64");
}

// Health
app.get("/", (_req, res) => {
  res.status(200).send("ok");
});

// CRC endpoint: GET /x-webhook?crc_token=...
app.get("/x-webhook", (req, res) => {
  try {
    const crcToken = req.query.crc_token;
    if (!crcToken) {
      return res.status(400).json({ error: "Missing crc_token" });
    }

    if (!X_WEBHOOK_CONSUMER_SECRET) {
      return res.status(500).json({ error: "X_WEBHOOK_CONSUMER_SECRET is not set" });
    }

    const responseToken =
      "sha256=" + hmacSha256Base64(String(crcToken), X_WEBHOOK_CONSUMER_SECRET);

    return res.status(200).json({ response_token: responseToken });
  } catch (e) {
    console.error("[crc] error:", e);
    return res.status(500).json({ error: "CRC failed" });
  }
});

// Для подписи нужен raw body
const webhookRawParser = express.raw({ type: "application/json", limit: "1mb" });

// POST webhook events
app.post("/x-webhook", webhookRawParser, async (req, res) => {
  try {
    if (!Buffer.isBuffer(req.body)) {
      return res.status(400).json({ ok: false, error: "Expected raw body buffer" });
    }

    const rawBody = req.body;
    const sigHeader = req.get("x-twitter-webhooks-signature") || "";

    // Проверка подписи (если секрет задан)
    if (X_WEBHOOK_CONSUMER_SECRET) {
      const expected = "sha256=" + hmacSha256Base64(rawBody, X_WEBHOOK_CONSUMER_SECRET);
      if (!sigHeader || sigHeader !== expected) {
        return res.status(401).json({ ok: false, error: "Invalid webhook signature" });
      }
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return res.status(400).json({ ok: false, error: "Invalid JSON" });
    }

    console.log("[x-webhook] event keys:", Object.keys(payload || {}));

    await notifyTelegram(payload);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[x-webhook] error:", e);
    return res.status(500).json({ ok: false, error: e.message || "Internal error" });
  }
});

async function notifyTelegram(payload) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;

  const text = formatAlert(payload);
  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text,
      disable_web_page_preview: true,
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Telegram send failed: ${resp.status} ${body}`);
  }
}

function formatAlert(payload) {
  const compact = JSON.stringify(payload, null, 2).slice(0, 3500);
  return `X webhook event received\n\n${compact}`;
}

app.listen(PORT, () => {
  console.log(`Listening on ${PORT}`);
});

