// LeakScope License Server — Cloudflare Worker
// ===============================================
// Handles: Creem webhook (付款→存 key) + /api/license/verify (客户端激活)
//
// KV binding required: LEAKSCOPE_KEYS (命名空间 ID 见 wrangler.toml)
// Secrets required (在 Cloudflare Dashboard → Settings → Variables and Secrets 里配置):
//   CREEM_WEBHOOK_SECRET = 从 Creem Dashboard Settings → Webhooks 里复制
//   CREEM_API_KEY = 从 Creem Dashboard Settings → API Keys 里复制（可选，留空也行）
// Variables:
//   ALLOWED_PRODUCT_IDS = prod_30urhTXPFHnMKBU56GiGvy  (用逗号分隔多个)

export default {
  async fetch(request, env, ctx) {
    const ALLOWED_PRODUCTS = (env.ALLOWED_PRODUCT_IDS || "prod_30urhTXPFHnMKBU56GiGvy")
      .split(",").map(s => s.trim());
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS — 桌面应用跨域调用
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(),
      });
    }

    // ─── Creem Webhook ─────────────────────────────────
    if (path === "/api/creem/webhook" && request.method === "POST") {
      return handleCreemWebhook(request, env);
    }

    // ─── Client: verify license key ────────────────────
    if (path === "/api/license/verify" && request.method === "POST") {
      return handleVerify(request, env);
    }

    // ─── Health check ───────────────────────────────────
    if (path === "/healthz") {
      return json({ ok: true, service: "leakscope-license" });
    }

    return json({ error: "Not found" }, 404);
  },
};

// ─── Creem Webhook Handler ────────────────────────────────
// 接收付款完成事件，把 Creem 自动生成的 license key 存到 KV
async function handleCreemWebhook(request, env) {
  const rawBody = await request.text();
  const signature = request.headers.get("creem-signature");

  // 1. HMAC-SHA256 签名验证
  if (!signature) {
    console.error("Webhook: missing creem-signature header");
    return json({ error: "Missing signature" }, 400);
  }

  const secret = env.CREEM_WEBHOOK_SECRET;
  if (!secret) {
    console.error("Webhook: CREEM_WEBHOOK_SECRET not configured");
    return json({ error: "Server misconfiguration" }, 500);
  }

  const valid = await verifyHmac(rawBody, secret, signature);
  if (!valid) {
    console.error("Webhook: signature mismatch");
    return json({ error: "Invalid signature" }, 401);
  }

  // 2. 解析 payload
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return json({ error: "Bad JSON" }, 400);
  }

  // 3. 只关心 checkout.completed
  const eventType = payload.eventType;
  if (eventType !== "checkout.completed") {
    return json({ ok: true, skipped: true, reason: `event=${eventType}` });
  }

  const checkout = payload.object || {};
  const productId = checkout.product?.id;
  const customerEmail = checkout.customer?.email;
  const customerName = checkout.customer?.name || customerEmail;
  const orderId = checkout.order?.id;

  // 4. 产品白名单检查
  if (!ALLOWED_PRODUCTS.includes(productId)) {
    console.log(`Webhook: product ${productId} not in allowlist, ignoring`);
    return json({ ok: true, skipped: true, reason: "product not allowed" });
  }

  // 5. 提取 Creem 生成的 license keys
  const licenseKeys = checkout.license_keys || [];
  if (licenseKeys.length === 0) {
    console.warn(`Webhook: no license keys in checkout ${orderId}`);
    return json({ ok: true, warning: "no license_keys field" });
  }

  // 6. 存到 KV
  const stored = [];
  for (const lk of licenseKeys) {
    const key = lk.key; // Creem 生成: ABCDE-FGHIJ-KLMNO-PQRST-UVWXY
    const record = {
      email: customerEmail,
      name: customerName,
      product_id: productId,
      product_name: checkout.product?.name,
      license_id: lk.id,       // lk_xxx
      activation_limit: lk.activation_limit,
      expires_at: lk.expires_at,
      order_id: orderId,
      sold_at: new Date().toISOString(),
      source: "creem",
      used: false,
    };

    await env.LEAKSCOPE_KEYS.put(key, JSON.stringify(record));
    stored.push({ key, license_id: lk.id });
  }

  console.log(`Webhook: stored ${stored.length} license(s) for ${customerEmail}`);

  return json({
    ok: true,
    message: `Stored ${stored.length} license key(s)`,
    licenses: stored.map(s => ({ license_id: s.license_id })), // 不回传 key
  });
}

// ─── Client Verify Handler ────────────────────────────────
// Rust 客户端调: POST { email, key } → { valid, plan, email, message, token }
async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ valid: false, message: "Bad JSON" }, 400);
  }

  const { email, key } = body;
  if (!email || !key) {
    return json({ valid: false, message: "Email and key required" }, 400);
  }

  const normalizedKey = key.trim().toUpperCase();
  const normalizedEmail = email.trim().toLowerCase();

  // 1. 从 KV 查
  const raw = await env.LEAKSCOPE_KEYS.get(normalizedKey);
  if (!raw) {
    return json({ valid: false, plan: "pro", message: "License key not found" });
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    return json({ valid: false, plan: "pro", message: "Corrupted license record" });
  }

  // 2. 邮箱必须匹配
  if (record.email.toLowerCase() !== normalizedEmail) {
    return json({ valid: false, plan: "pro", message: "Email does not match this license key" });
  }

  // 3. 过期检查
  if (record.expires_at) {
    const expires = new Date(record.expires_at).getTime();
    if (Date.now() > expires) {
      return json({ valid: false, plan: "pro", message: "License key expired" });
    }
  }

  // 4. 生成短期活跃 token（客户端存本地用于宽限期验证）
  const tokenPayload = {
    e: normalizedEmail,
    k: normalizedKey,
    p: record.product_name || "LeakScope Pro",
    t: Date.now(),
  };
  const token = btoa(JSON.stringify(tokenPayload));

  return json({
    valid: true,
    plan: record.product_name || "pro",
    email: normalizedEmail,
    message: "License verified ✓",
    token,
  });
}

// ─── Helpers ──────────────────────────────────────────────

async function verifyHmac(payload, secret, signature) {
  const enc = new TextEncoder();
  const keyData = enc.encode(secret);
  const payloadData = enc.encode(payload);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const result = await crypto.subtle.verify(
    "HMAC", cryptoKey, hexToBytes(signature), payloadData
  );
  return result;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json" },
  });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
