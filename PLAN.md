# LeakScope — GitHub Secret Scanner

> Desktop app that scans your GitHub repos for leaked API keys, tokens, passwords, and private certs.

---

## One-liner

Tauri 桌面端 + GitHub OAuth → 一键扫所有 repo（public + private）→ 可视化泄露 → 一键跳转撤销。

## Why this exists

| Competitor | Pain | LeakScope |
|-----------|------|-----------|
| GitHub Secret Scanning | Private repos need **$49/committer/mo** (GHAS) | $29 perpetual → unlimited repos |
| TruffleHog / gitleaks | CLI only — Docker, env, JSON reports | Desktop GUI → 3 clicks |
| GitGuardian | Free = 25 devs, Growth = $5K+/yr | Pro $29 unlimited repos |
| Aikido | $350/mo, heavy, K8s | Lightweight desktop, offline OK |

**Core hook**: `GitHub Advanced Security $588/committer/year → LeakScope $29 one-time`

---

## Tech Stack

- **Frontend**: Tauri v2 + React 19 + Vite 8 + TailwindCSS
- **Backend**: Rust (Octocrab for GitHub API, regex + optional RE2 for patterns)
- **Scan Engine**: Fork gitleaks rules (MIT) — 120+ patterns
- **License**: Reuse MagiDiva Cloudflare Worker + Creem checkout
- **Platform**: Windows first, macOS native

## Architecture

```
┌──────────────────────────────────────────────┐
│  Tauri v2 + React 19 frontend                │
│  ├── GitHub OAuth (device flow)               │
│  ├── Repo list (public + private + orgs)      │
│  ├── Scan progress + leak visualization       │
│  │   (file tree + line number + code snippet) │
│  ├── Token validity verify (call original API)│
│  └── Revocation guide (platform → URL mapping) │
└─────────────────┬────────────────────────────┘
                  │ invoke()
┌─────────────────▼────────────────────────────┐
│  Rust backend                                 │
│  ├── GitHub API v3 (Octocrab)                  │
│  ├── Secret pattern engine (120+ regex)        │
│  ├── git history scan (sparse clone, Pro only) │
│  ├── Token verify (reqwest)                    │
│  └── License gating (reuse Worker)             │
└───────────────────────────────────────────────┘
```

---

## Feature Split (Community vs Pro)

| Feature | Community (free) | Pro ($29 perpetual) |
|---------|------------------|---------------------|
| GitHub OAuth | ✅ | ✅ |
| Repo count | ≤ 5 | Unlimited |
| Scan scope | HEAD only (current commit) | HEAD + **git history** |
| Leak visualization | File + line number | + **code snippet + blame author** |
| Token verify | ❌ | ✅ Call original API, check if active |
| Revocation guide | Basic list | + **one-click platform revoke URL** |
| Export report | ❌ | ✅ JSON / PDF |
| Scheduled scan | ❌ | ✅ Daily background cron |
| Pattern count | 50 | 120+ |

## Pricing

| Tier | Price | Target |
|------|-------|--------|
| Community | Free | Students, OSS maintainers, small projects |
| Pro | **$29 perpetual** | Solo devs, small teams ≤20 |
| Team (future) | $299/yr | 5–50 people, org role sync |

---

## 120+ Secret Pattern Categories

Fork from gitleaks config (MIT):

- **Cloud**: AWS Access/Secret Key, GCP Service Account, Azure AD, DigitalOcean, Cloudflare, IBM Cloud
- **Payment**: Stripe Live/Test Key, Square, Adyen
- **AI**: OpenAI, Anthropic, Google AI, Cohere
- **Dev**: GitHub Personal Token (4 types), GitLab, Bitbucket, Gitea
- **Communication**: Slack Bot/User/Webhook Token, Discord, Telegram, Twilio, SendGrid, Mailgun
- **Database**: MongoDB URI, Redis, MySQL, PostgreSQL connection strings
- **Monitoring**: Datadog, New Relic, Dynatrace, Grafana
- **Infra**: Docker Hub Token, Kubeconfig, SSH Private Key, TLS Cert
- **Misc**: JWT, base64-encoded keys, PEM blocks

---

## 4-Week MVP Timeline

| Week | Deliverable |
|------|-------------|
| **W1** | GitHub OAuth + Repo list + Basic HEAD scan + 50 patterns |
| **W2** | Leak visualization (file tree + line + snippet) + full gitleaks pattern set |
| **W3** | Pro features: git history scan + token verify + revoke guide |
| **W4** | UI polish + dark/light theme + Landing Page + Product Hunt |

---

## Reuse from MagiDiva

| Asset | Status |
|-------|--------|
| Tauri v2 + Rust + React 19 stack | ✅ Same workspace, new crate |
| License Worker (Cloudflare) | ✅ Change product_id |
| Creem checkout | ✅ New product |
| Landing page pattern | ✅ Dark theme + violet accent |
| GitHub Actions CI | ✅ Windows + macOS build |
| Icon design pipeline | ✅ 50 files auto-generated |

## Naming

- **LeakScope** — recommended, `leakscope.com` available
- Alternatives: SecretLens, RepoGuard, KeyHunter

---

## Critical Decisions

1. **License server**: reuse MagiDiva Worker → save 1 week
2. **Scan engine**: fork gitleaks rules (MIT) → don't reinvent regex
3. **git history scan**: use `git clone --filter=blob:none --no-checkout` sparse clone → fast, no full download
4. **Token verify**: don't actually use leaked tokens — just check HTTP 200 vs 401/403
5. **Device flow**: GitHub OAuth device flow → no redirect URI needed, perfect for desktop apps

---

## Risks

| Risk | Mitigation |
|------|------------|
| GitHub rate limits | Use Conditional Requests (`If-None-Match`) + local ETag cache |
| False positives | Each pattern has entropy threshold + keyword context filter |
| Large repos (Linux kernel scale) | Stream file contents, don't load entire repo into memory |
| Legal — scanning your own repos | Clearly EULA: "only scan repos you own or have explicit permission to scan" |

---

## Week 1 TODO

- [ ] Scaffold Tauri v2 + React 19 + Tailwind
- [ ] Add Octocrab + OAuth device flow
- [ ] GitHub device code → poll → get token → list repos
- [ ] Download file contents (via GitHub API) → regex scan → show leaks
- [ ] 50 basic patterns
- [ ] First working end-to-end demo
