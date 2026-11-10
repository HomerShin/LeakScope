# LeakScope

> Scan GitHub repos for leaked secrets — before attackers find them.

LeakScope is a lightweight desktop app built with **Tauri v2 + React 19 + Rust** that scans both public and private GitHub repositories for accidentally committed secrets: API keys, passwords, private certificates, database URIs, and more across **78+ service providers**.

## ✨ Features

- 🔍 **78+ Secret Patterns** — AWS, Stripe, OpenAI, Anthropic, GitHub, Slack, Twilio, MongoDB, DigitalOcean, Cloudflare, and many more
- 🔐 **Private Repo Support** — GitHub Device Flow authentication
- 🪪 **Masked Output** — Secrets are masked by default in the UI
- 🚨 **One-Click Revoke** — Direct links to each provider's credential management page
- 🕵️ **Git History Scan** (Pro) — Find secrets that were committed and later deleted
- ✅ **Live Key Verification** (Pro) — Check if discovered keys are still active

## 🛠️ Tech Stack

- **Tauri 2** — Desktop framework (~12MB binary)
- **React 19 + Vite 8** — Frontend
- **TypeScript 6** — Type-safe UI
- **Rust** — High-performance scanner backend
- **Tailwind CSS 4** — Styling

## 📥 Download

See [https://homershin.github.io/LeakScope](https://homershin.github.io/LeakScope) for the latest release.

## 🏗️ Build from Source

```bash
# Prerequisites: Node 20+, Rust stable, pnpm

# Install dependencies
pnpm install

# Run in dev mode
pnpm tauri dev

# Build release exe
pnpm release

# Build installer (.msi)
pnpm installer
```

## 📜 License

MIT © LeakScope

---

❤️ **Like LeakScope?** Upgrade to [Pro](https://www.creem.io/product/prod_30urhTXPFHnMKBU56GiGvy) to support development and unlock advanced features.
