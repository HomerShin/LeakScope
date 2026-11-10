# LeakScope License Worker — 部署指南

## 需要你手动做的事（都在 Cloudflare Dashboard 里）

### 1. 创建 KV Namespace
```
Cloudflare Dashboard → Storage & Databases → KV → Create namespace
Name: leakscope-keys
```
创建完后**复制 Namespace ID**（一串类似 `a1b2c3d4...` 的字符串）。

### 2. 部署 Worker（两种方式选一种）

#### 方式 A：Cloudflare Dashboard 里直接粘贴
1. Workers & Pages → Create application → Create Worker
2. Name: `leakscope-license`（或你想要的名字）
3. 把 `worker.js` 的内容粘贴到编辑器
4. 把 `wrangler.toml` 里的 KV namespace ID 替换成你刚才创建的那个
5. Settings → Bindings → KV Namespace Bindings → Add binding
   - Variable name: `LEAKSCOPE_KEYS`
   - KV Namespace: 选你创建的那个
6. Settings → Variables and Secrets → Production variables → Add
   - Name: `ALLOWED_PRODUCT_IDS`
   - Value: `prod_30urhTXPFHnMKBU56GiGvy`
7. Settings → Variables and Secrets → Production secrets → Add
   - Name: `CREEM_WEBHOOK_SECRET`
   - Value: 从 Creem Dashboard → Settings → Webhooks 里复制 Webhook Secret
8. Deploy

#### 方式 B：wrangler CLI
```bash
# 1. 安装 wrangler
npm install -g wrangler
wrangler login

# 2. 创建 KV namespace（输出里会有 id）
wrangler kv namespace create leakscope-keys

# 3. 编辑 wrangler.toml 把 id 填进去

# 4. 设 secret
wrangler secret put CREEM_WEBHOOK_SECRET
# 粘贴 Creem 的 webhook secret，回车

# 5. 部署
wrangler deploy
```

### 3. 在 Creem Dashboard 配 Webhook
```
Creem Dashboard → Settings → Webhooks → Add endpoint

URL: https://<你的 worker 域名>.workers.dev/api/creem/webhook
     或者你自定义的域名，比如 https://magidiva-license.805998855.workers.dev/api/creem/webhook

Events:
  ✅ checkout.completed
```

### 4. 测试流程

#### 手动测试 webhook
Creem Dashboard → Settings → Webhooks → 你的 endpoint → **Send test event**
应该返回 200，Worker 日志里能看到 `stored N license(s)`

#### 手动测试 verify
```bash
curl -X POST https://<worker>/api/license/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "key": "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY"}'
```
如果 KV 里存了这个 key，返回 `{"valid": true, ...}`

#### 端到端测试
1. Creem Dashboard 里给产品开 Test Mode
2. 用测试卡 `4242 4242 4242 4242` 完成 $39 支付
3. Creem 会自动发 webhook → Worker 存 key
4. Worker 应该返回 200
5. 你会收到邮件，里面有 Creem 生成的 license key
6. 在 LeakScope Pro build 里输入 email + key → 激活成功 ✅

## Worker URL 在哪里看
Cloudflare Dashboard → Workers & Pages → 你的 Worker → **Overview** 页面顶部有 `.workers.dev` 子域名。

## LeakScope 客户端还要改吗？
**不用。** Rust 代码里 `license.rs` 的 `activate(email, key)` 已经能调 Worker 的 `/api/license/verify`。只要 Worker URL 对得上（`LICENSE_SERVER` 常量），Creem 生成的 key 就能验证通过。

## 安全注意
- `CREEM_WEBHOOK_SECRET` 是敏感信息，存在 Cloudflare secret 里，**永远不要硬编码**
- Worker 签名验证通过 HMAC-SHA256 防篡改，别人伪造不了 webhook
- KV 的 value 里存了用户 email，Worker 只在验证时比对，不返回给任何人
