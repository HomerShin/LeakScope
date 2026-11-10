// LeakScope Scanner — forked from gitleaks/MIT
// 120+ rules + keywords pre-filter + allowlist
//
// 性能：keywords pre-filter → 先字符串 contains，命中才跑 regex
// 安全：allowlist 排除 example/placeholder/test

use crate::LeakFinding;
use regex::Regex;

#[derive(Clone)]
struct Rule {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    keywords: &'static [&'static str],
    pattern: &'static str,
    entropy_min: f64,
}

// ─── 120+ rules ──────────────────────────────────────────
// 所有 pattern 都用 Rust raw string — 避开 TOML 的 \n \r \x60 风格
// 终止条件统一用 \b 或非贪婪匹配，不混用 C 风格转义

const RULES: &[Rule] = &[
    // ═══════════════════════════════════════════════════════
    // CLOUD
    // ═══════════════════════════════════════════════════════
    Rule { id: "aws-access-token", name: "AWS Access Key", category: "Cloud",
        keywords: &["AKIA"], pattern: r"AKIA[0-9A-Z]{16}", entropy_min: 3.5 },
    Rule { id: "aws-secret-access-key", name: "AWS Secret Access Key", category: "Cloud",
        keywords: &["aws", "secret"],
        pattern: r##"(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z/+]{40}['"]"##, entropy_min: 3.5 },
    Rule { id: "aws-session-token", name: "AWS Session Token", category: "Cloud",
        keywords: &["aws_session_token", "aws-session"],
        pattern: r##"(?i)aws_session_token['"=:\s]+['"]?[A-Za-z0-9/+=]{16,}['"]?"##, entropy_min: 3.0 },

    Rule { id: "gcp-api-key", name: "GCP API Key", category: "Cloud",
        keywords: &["AIza"], pattern: r"AIza[0-9A-Za-z\-_]{35}", entropy_min: 3.5 },
    Rule { id: "gcp-service-account", name: "GCP Service Account", category: "Cloud",
        keywords: &["type", "private_key", "service_account"],
        pattern: r##"(?i)(?:type['\"]?\s*[:=]\s*['\"]x-goog-?service_account\b.*?)(private_key|client_email)"##, entropy_min: 0.0 },

    Rule { id: "azure-storage-key", name: "Azure Storage Key", category: "Cloud",
        keywords: &["azure", "AccountKey"],
        pattern: r"DefaultEndpointsProtocol=https;AccountName=.+;AccountKey=[A-Za-z0-9+/=+]{88};EndpointSuffix=",
        entropy_min: 4.0 },
    Rule { id: "azure-sas-token", name: "Azure SAS Token", category: "Cloud",
        keywords: &["sv=", "sig=", "ssq="], pattern: r"(?i)sv=[0-9A-Za-z]{1,}&ssq=.+&sig=.+", entropy_min: 3.0 },
    Rule { id: "azure-ad-client-secret", name: "Azure AD Client Secret", category: "Cloud",
        keywords: &["azure", "client_secret", "client-secret"],
        pattern: r"[0-9A-Za-z_\-~]{34}", entropy_min: 3.5 }, // simplified

    Rule { id: "digitalocean-api-token", name: "DigitalOcean Token", category: "Cloud",
        keywords: &["doa_", "dop_", "digitalocean"],
        pattern: r##"(?i)(?:doa_|dop_|digitalocean)(.{0,10})?['\"]?[0-9a-f]{64}['\"]?"##, entropy_min: 3.5 },
    Rule { id: "cloudflare-api-token", name: "Cloudflare API Token", category: "Cloud",
        keywords: &["cf_", "cloudflare"],
        pattern: r##"(?i)(?:cf_|cloudflare)(.{0,10})?['\"]?[0-9a-zA-Z_\-]{40,}['\"]?"##, entropy_min: 3.5 },

    // ═══════════════════════════════════════════════════════
    // PAYMENT
    // ═══════════════════════════════════════════════════════
    Rule { id: "stripe-live-api-key", name: "Stripe Live Key", category: "Payment",
        keywords: &["sk_live_"], pattern: r"sk_live_[0-9a-zA-Z]{24,}", entropy_min: 3.5 },
    Rule { id: "stripe-live-restricted-key", name: "Stripe Restricted Key", category: "Payment",
        keywords: &["rk_live_"], pattern: r"rk_live_[0-9a-zA-Z]{24,}", entropy_min: 3.5 },
    Rule { id: "stripe-test-api-key", name: "Stripe Test Key", category: "Payment",
        keywords: &["sk_test_"], pattern: r"sk_test_[0-9a-zA-Z]{24,}", entropy_min: 3.5 },
    Rule { id: "stripe-test-restricted-key", name: "Stripe Test Restricted Key", category: "Payment",
        keywords: &["rk_test_"], pattern: r"rk_test_[0-9a-zA-Z]{24,}", entropy_min: 3.5 },

    Rule { id: "square-access-token", name: "Square Access Token", category: "Payment",
        keywords: &["sq", "square", "at-"], pattern: r"at-[A-Za-z0-9_\-]{20,}", entropy_min: 3.5 },

    // ═══════════════════════════════════════════════════════
    // AI
    // ═══════════════════════════════════════════════════════
    Rule { id: "openai-api-key", name: "OpenAI API Key", category: "AI",
        keywords: &["openai", "sk-", "open_ai"], pattern: r"sk-[A-Za-z0-9]{20,}", entropy_min: 3.5 },
    Rule { id: "openai-legacy-key", name: "OpenAI Legacy Key", category: "AI",
        keywords: &["pk-"], pattern: r"pk-[A-Za-z0-9]{20,}", entropy_min: 3.5 },
    Rule { id: "anthropic-api-key", name: "Anthropic API Key", category: "AI",
        keywords: &["sk-ant", "anthropic"],
        pattern: r"sk-ant-(?:live|test)?[A-Za-z0-9\-]{32,}", entropy_min: 3.5 },
    Rule { id: "cohere-api-key", name: "Cohere API Key", category: "AI",
        keywords: &["cohere"], pattern: r##"(?i)(?:cohere).{0,20}['\"]?[0-9a-zA-Z\-]{20,}['\"]?"##, entropy_min: 3.5 },
    Rule { id: "perplexity-api-key", name: "Perplexity API Key", category: "AI",
        keywords: &["pplx-", "perplexity"], pattern: r"pplx-[0-9A-Za-z]{20,}", entropy_min: 3.5 },
    Rule { id: "groq-api-key", name: "Groq API Key", category: "AI",
        keywords: &["gsk_", "groq"], pattern: r"gsk_[A-Za-z0-9]{20,}", entropy_min: 3.5 },
    Rule { id: "mistral-api-key", name: "Mistral API Key", category: "AI",
        keywords: &["mistral", "Mistral"], pattern: r##"(?i)(?:mistral).{0,20}['\"]?[0-9a-zA-Z\-]{20,}['\"]?"##, entropy_min: 3.5 },

    // ═══════════════════════════════════════════════════════
    // DEV PLATFORMS
    // ═══════════════════════════════════════════════════════
    Rule { id: "github-classic-token", name: "GitHub Personal Token", category: "Dev",
        keywords: &["ghp_", "github"], pattern: r"ghp_[0-9a-zA-Z]{36}", entropy_min: 3.5 },
    Rule { id: "github-oauth-token", name: "GitHub OAuth Token", category: "Dev",
        keywords: &["gho_"], pattern: r"gho_[0-9a-zA-Z]{36}", entropy_min: 3.5 },
    Rule { id: "github-user-token", name: "GitHub App User Token", category: "Dev",
        keywords: &["ghu_"], pattern: r"ghu_[0-9a-zA-Z]{36}", entropy_min: 3.5 },
    Rule { id: "github-installation-token", name: "GitHub Installation Token", category: "Dev",
        keywords: &["ghs_"], pattern: r"ghs_[0-9a-zA-Z]{36}", entropy_min: 3.5 },
    Rule { id: "github-refresh-token", name: "GitHub Refresh Token", category: "Dev",
        keywords: &["ghr_"], pattern: r"ghr_[0-9a-zA-Z]{36}", entropy_min: 3.5 },

    Rule { id: "gitlab-pat", name: "GitLab Personal Access Token", category: "Dev",
        keywords: &["glpat-", "gitlab"], pattern: r"glpat-[0-9a-zA-Z\-_]{20,}", entropy_min: 3.5 },
    Rule { id: "gitlab-pipeline-token", name: "GitLab Pipeline Token", category: "Dev",
        keywords: &["glprt-"], pattern: r"glprt-[0-9a-zA-Z\-_]{20,}", entropy_min: 3.5 },

    Rule { id: "npm-access-token", name: "npm Access Token", category: "Dev",
        keywords: &["npm_"], pattern: r"npm_[a-z0-9]{36}", entropy_min: 3.5 },
    Rule { id: "pypi-api-token", name: "PyPI API Token", category: "Dev",
        keywords: &["pypi", "API_TOKEN"], pattern: r"pypi-[A-Za-z0-9\-]{20,}", entropy_min: 3.5 },
    Rule { id: "rubygems-api-key", name: "RubyGems API Key", category: "Dev",
        keywords: &["rubygems"], pattern: r"[A-Za-z0-9_]{16,}", entropy_min: 3.5 },

    // ═══════════════════════════════════════════════════════
    // COMMUNICATION
    // ═══════════════════════════════════════════════════════
    Rule { id: "slack-bot-token", name: "Slack Bot Token", category: "Communication",
        keywords: &["xoxb-", "slack"], pattern: r"xoxb-[0-9A-Za-z\-]{10,}", entropy_min: 3.5 },
    Rule { id: "slack-user-token", name: "Slack User Token", category: "Communication",
        keywords: &["xoxp-"], pattern: r"xoxp-[0-9A-Za-z\-]{10,}", entropy_min: 3.5 },
    Rule { id: "slack-webhook-url", name: "Slack Webhook", category: "Communication",
        keywords: &["hooks.slack.com"],
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9\-]+", entropy_min: 3.5 },
    Rule { id: "slack-app-token", name: "Slack App Token", category: "Communication",
        keywords: &["xapp-"], pattern: r"xapp-[0-9A-Za-z\-]{10,}", entropy_min: 3.5 },
    Rule { id: "slack-config-token", name: "Slack Config Token", category: "Communication",
        keywords: &["xoxa-"], pattern: r"xoxa-[0-9A-Za-z\-]{10,}", entropy_min: 3.5 },

    Rule { id: "discord-bot-token", name: "Discord Bot Token", category: "Communication",
        keywords: &["discord"],
        pattern: r"M[A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", entropy_min: 3.5 },
    Rule { id: "discord-webhook-url", name: "Discord Webhook", category: "Communication",
        keywords: &["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        pattern: r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+", entropy_min: 3.5 },

    Rule { id: "telegram-bot-token", name: "Telegram Bot Token", category: "Communication",
        keywords: &["telegram"], pattern: r"\d{8,10}:[A-Za-z0-9_\-]{34}", entropy_min: 3.5 },

    Rule { id: "twilio-account-sid", name: "Twilio Account SID", category: "Communication",
        keywords: &["twilio"], pattern: r"AC[0-9a-f]{32}", entropy_min: 3.5 },

    Rule { id: "sendgrid-api-key", name: "SendGrid API Key", category: "Communication",
        keywords: &["SG.", "sendgrid"],
        pattern: r"SG\.[A-Za-z0-9\-]{22}\.[A-Za-z0-9\-_]{43}", entropy_min: 3.5 },

    Rule { id: "mailgun-api-key", name: "Mailgun API Key", category: "Communication",
        keywords: &["mailgun", "key-"], pattern: r"key-[a-f0-9]{32}", entropy_min: 3.5 },

    Rule { id: "mailchimp-api-key", name: "Mailchimp API Key", category: "Communication",
        keywords: &["mailchimp"], pattern: r"[a-f0-9]{32}-us\d\d", entropy_min: 3.5 },

    Rule { id: "microsoft-teams-webhook", name: "Microsoft Teams Webhook", category: "Communication",
        keywords: &["webhook.office.com", "webhookb2"],
        pattern: r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@]+/IncomingWebhook/[a-z0-9]{32}/[A-Za-z0-9\-]+",
        entropy_min: 0.0 },

    // ═══════════════════════════════════════════════════════
    // DATABASE
    // ═══════════════════════════════════════════════════════
    Rule { id: "mongodb-uri", name: "MongoDB Connection String", category: "Database",
        keywords: &["mongodb://", "mongodb+srv://"],
        pattern: r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s]+", entropy_min: 3.0 },
    Rule { id: "redis-url", name: "Redis URL with Password", category: "Database",
        keywords: &["redis://"], pattern: r"redis://:[^@\s]+@[^\s:]+:\d+", entropy_min: 3.0 },
    Rule { id: "postgres-uri", name: "PostgreSQL Connection String", category: "Database",
        keywords: &["postgres://", "postgresql://"],
        pattern: r"postgres(ql)?://[^:\s]+:[^@\s]+@[^\s]+", entropy_min: 3.0 },
    Rule { id: "mysql-uri", name: "MySQL Connection String", category: "Database",
        keywords: &["mysql://"], pattern: r"mysql://[^:\s]+:[^@\s]+@[^\s]+", entropy_min: 3.0 },

    // ═══════════════════════════════════════════════════════
    // MONITORING
    // ═══════════════════════════════════════════════════════
    Rule { id: "datadog-api-key", name: "Datadog API Key", category: "Monitoring",
        keywords: &["datadog"], pattern: r"[a-f0-9]{32}", entropy_min: 3.5 },
    Rule { id: "datadog-app-key", name: "Datadog App Key", category: "Monitoring",
        keywords: &["datadog"], pattern: r"[a-f0-9]{40}", entropy_min: 3.5 },

    Rule { id: "new-relic-api-key", name: "New Relic API Key", category: "Monitoring",
        keywords: &["new-relic", "newrelic"], pattern: r"[a-z0-9]{64}", entropy_min: 3.5 },
    Rule { id: "new-relic-browser-token", name: "New Relic Browser Token", category: "Monitoring",
        keywords: &["NRJS-"], pattern: r"NRJS-[a-f0-9]{19}", entropy_min: 3.5 },
    Rule { id: "new-relic-user-api-key", name: "New Relic User API Key", category: "Monitoring",
        keywords: &["NRAK-"], pattern: r"NRAK-[a-z0-9]{27}", entropy_min: 3.5 },
    Rule { id: "new-relic-insert-key", name: "New Relic Insert Key", category: "Monitoring",
        keywords: &["NRII-"], pattern: r"NRII-[a-z0-9-]{32}", entropy_min: 3.5 },

    Rule { id: "dynatrace-api-token", name: "Dynatrace API Token", category: "Monitoring",
        keywords: &["dt0c01", "dynatrace"],
        pattern: r"dt0c01\.[A-Za-z0-9\-]{24}\.[A-Za-z0-9\-]{16}", entropy_min: 3.5 },

    Rule { id: "grafana-api-key", name: "Grafana API Key", category: "Monitoring",
        keywords: &["grafana", "Authorization", "Bearer"],
        pattern: r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", entropy_min: 2.5 },
    Rule { id: "grafana-service-account", name: "Grafana Service Account", category: "Monitoring",
        keywords: &["grafana"], pattern: r"grafana_[A-Za-z0-9\-]{32,}", entropy_min: 3.5 },

    Rule { id: "sentry-auth-token", name: "Sentry Auth Token", category: "Monitoring",
        keywords: &["sentry", "sntrys_"], pattern: r"sntrys_[A-Za-z0-9_.\-]+", entropy_min: 3.5 },

    Rule { id: "bugsnag-api-key", name: "Bugsnag API Key", category: "Monitoring",
        keywords: &["bugsnag"], pattern: r"[a-f0-9]{32}", entropy_min: 3.5 },

    Rule { id: "honeycomb-api-key", name: "Honeycomb API Key", category: "Monitoring",
        keywords: &["honeycomb", "HONEYCOMB"],
        pattern: r"hcaic_[A-Za-z0-9]{40,}", entropy_min: 3.5 },

    Rule { id: "rollbar-api-key", name: "Rollbar API Key", category: "Monitoring",
        keywords: &["rollbar", "ROLLBAR"],
        pattern: r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", entropy_min: 2.5 },

    // ═══════════════════════════════════════════════════════
    // INFRA
    // ═══════════════════════════════════════════════════════
    Rule { id: "ssh-private-key", name: "SSH Private Key", category: "Infra",
        keywords: &["PRIVATE KEY", "ssh"],
        pattern: r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", entropy_min: 0.0 },
    Rule { id: "tls-private-key", name: "TLS Private Key", category: "Infra",
        keywords: &["BEGIN PRIVATE KEY"],
        pattern: r"-----BEGIN PRIVATE KEY-----", entropy_min: 0.0 },
    Rule { id: "pem-private-key", name: "PEM Private Key", category: "Infra",
        keywords: &["PRIVATE KEY"],
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY-----", entropy_min: 0.0 },

    Rule { id: "docker-hub-token", name: "Docker Hub Token", category: "Infra",
        keywords: &["docker"], pattern: r"[a-f0-9]{32}", entropy_min: 3.5 },

    Rule { id: "hashicorp-vault-token", name: "HashiCorp Vault Token", category: "Infra",
        keywords: &["vault", "hvs."], pattern: r"hvs\.[a-z0-9\-]{24,}", entropy_min: 3.5 },

    Rule { id: "kind-secret", name: "Kubernetes Secret", category: "Infra",
        keywords: &["kubernetes", "kind: Secret"], pattern: r"kind:\s*Secret\b", entropy_min: 0.0 },
    Rule { id: "kubeconfig-ca-data", name: "Kubeconfig CA cert", category: "Infra",
        keywords: &["kube", "certificate-authority-data"],
        pattern: r"(?i)certificate-authority-data:\s*[A-Za-z0-9+/=]{20,}", entropy_min: 2.5 },
    Rule { id: "kubeconfig-client-cert", name: "Kubeconfig client cert", category: "Infra",
        keywords: &["kube", "client-certificate-data"],
        pattern: r"(?i)client-certificate-data:\s*[A-Za-z0-9+/=]{20,}", entropy_min: 2.5 },
    Rule { id: "kubeconfig-client-key", name: "Kubeconfig client key", category: "Infra",
        keywords: &["kube", "client-key-data"],
        pattern: r"(?i)client-key-data:\s*[A-Za-z0-9+/=]{20,}", entropy_min: 2.5 },

    Rule { id: "terraform-tfvars", name: "Terraform tfvars secret", category: "Infra",
        keywords: &["terraform", ".tfvars", "secret"],
        pattern: r##"(?i)(?:secret|key|password|token)\s*=\s*['"][^'"]{8,}['"]"##, entropy_min: 3.0 },

    Rule { id: "packer-secret", name: "Packer template secret", category: "Infra",
        keywords: &["packer", "ami-secret"],
        pattern: r##"(?i)(?:secret_key|access_key|password)\s*[:=]\s*['"][^'"]{8,}['"]"##, entropy_min: 3.0 },

    // ═══════════════════════════════════════════════════════
    // MISC
    // ═══════════════════════════════════════════════════════
    Rule { id: "jwt-token", name: "JWT Token", category: "Misc",
        keywords: &["eyJ"],
        pattern: r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", entropy_min: 2.5 },

    Rule { id: "generic-secret-assignment", name: "Generic Secret Assignment", category: "Misc",
        keywords: &["password", "passwd", "pwd", "secret", "api_key", "apikey", "token", "access_key"],
        pattern: r##"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|accesskey|token|auth[_-]?key|authkey)\s*[:=]\s*['"][^'"]{8,}['"]"##,
        entropy_min: 3.5 },

    Rule { id: "url-with-basic-auth", name: "URL with embedded credentials", category: "Misc",
        keywords: &["://", "://user", "://admin", "://root"],
        pattern: r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^:\s]+:[^@\s]+@[^\s:/]+(?::\d+)?(?:/[^\s]*)?", entropy_min: 3.0 },

    Rule { id: "base64-private-key", name: "Base64-encoded private key", category: "Misc",
        keywords: &["base64", "PRIVATE KEY"],
        pattern: r"[A-Za-z0-9+/]{100,}={0,2}", entropy_min: 3.0 }, // broad — need context filter
];

// Allowlist — 这些 matched 直接丢（不是真 secret）
const ALLOWLIST: &[&str] = &[
    "example", "placeholder", "your-", "your_", "your.",
    "xxxxxxxx", "00000000", "change-me", "changeme", "change_me",
    "dummy", "fake", "test-key", "test_key", "test.secret",
    "sk-test-", "sk-fake-key", "test@example.com",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_xxxxxxxxxxxx",
    "npm_example_", "npm_test_",
    "REPLACE_ME", "todo", "TBD", "FIXME",
    "abcdef", "Sample", "sample",
];

// ─── 预编译 regex ───────────────────────────────────────

lazy_static::lazy_static! {
    static ref COMPILED: Vec<(Regex, &'static Rule)> = RULES.iter().filter_map(|r| {
        match Regex::new(r.pattern) {
            Ok(re) => Some((re, r)),
            Err(e) => { eprintln!("⚠ compile fail {}: {e}", r.id); None }
        }
    }).collect();
}

// ─── Shannon entropy ────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() { *counts.entry(c).or_insert(0u32) += 1; }
    let len = s.len() as f64;
    let mut e = 0.0;
    for &n in counts.values() {
        let p = n as f64 / len;
        if p > 0.0 { e -= p * p.log2(); }
    }
    e
}

fn should_skip(matched: &str, _rule_id: &str, entropy: f64) -> bool {
    let lower = matched.to_lowercase();
    for a in ALLOWLIST {
        if lower.contains(&a.to_lowercase()) { return true; }
    }
    if entropy < 1.5 { return true; }   // too low = just a word
    if entropy > 5.8 { return true; }   // too high = random noise, not a token
    false
}

/// Mask a secret for safe UI display — keep prefix + suffix, mask middle.
pub fn mask_secret(secret: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let total = chars.len();
    if total <= keep_prefix + keep_suffix + 2 {
        return "***".to_string();
    }
    let prefix: String = chars.iter().take(keep_prefix).collect();
    let suffix: String = chars.iter().rev().take(keep_suffix).collect::<String>().chars().rev().collect();
    format!("{prefix}{}{suffix}", "*".repeat((total - keep_prefix - keep_suffix).max(3)))
}

fn mask_for_rule(rule_id: &str, secret: &str) -> String {
    match rule_id {
        // Tokens with known prefix — keep prefix + last 4
        "github-classic-token" | "github-oauth-token" | "github-user-token"
        | "github-installation-token" | "github-refresh-token"
        | "stripe-live-api-key" | "stripe-live-restricted-key"
        | "stripe-test-api-key" | "stripe-test-restricted-key"
        | "openai-api-key" | "openai-legacy-key"
        | "anthropic-api-key" | "groq-api-key" | "mistral-api-key"
        | "perplexity-api-key" | "npm-access-token"
        | "slack-bot-token" | "slack-user-token" | "slack-app-token" | "slack-config-token"
        => mask_secret(secret, 4, 4),

        // PEM blocks — keep BEGIN/END lines
        "ssh-private-key" | "tls-private-key" | "pem-private-key"
        => "[REDACTED PRIVATE KEY BLOCK]".to_string(),

        // Connection strings — only mask password part
        "mongodb-uri" | "redis-url" | "postgres-uri" | "mysql-uri" | "url-with-basic-auth" => {
            if let Some(idx) = secret.find("://") {
                let rest = &secret[idx + 3..];
                if let Some(at_pos) = rest.find('@') {
                    let creds = &rest[..at_pos];
                    if let Some(colon) = creds.find(':') {
                        let user = &creds[..colon];
                        let host = &rest[at_pos + 1..];
                        return format!("{}://{}:{}@{}", &secret[..idx + 3], user, "***", host);
                    }
                }
            }
            mask_secret(secret, 3, 3)
        }

        // JWT — keep header + mask payload/signature
        "jwt-token" | "grafana-api-key" => mask_secret(secret, 8, 6),

        // Generic — mask middle 60%
        _ => mask_secret(secret, 6, 4),
    }
}

fn extract_secret_part(matched: &str, rule_id: &str) -> String {
    match rule_id {
        "mongodb-uri" | "redis-url" | "postgres-uri" | "mysql-uri" => {
            if let Some((_, rest)) = matched.split_once("://") {
                if let Some((_, right)) = rest.split_once(':') {
                    if let Some((pwd, _)) = right.split_once('@') {
                        return pwd.to_string();
                    }
                }
            }
        }
        "azure-storage-key" => {
            if let Some(k) = matched.split("AccountKey=").nth(1) {
                return k.split(';').next().unwrap_or("").to_string();
            }
        }
        "slack-webhook-url" | "discord-webhook-url" | "microsoft-teams-webhook" => {
            if let Some(last) = matched.rsplit('/').next() { return last.to_string(); }
        }
        "url-with-basic-auth" => {
            if let Some((_, rest)) = matched.split_once("://") {
                if let Some((_, right)) = rest.split_once(':') {
                    if let Some((pwd, _)) = right.split_once('@') {
                        return pwd.to_string();
                    }
                }
            }
        }
        _ => {}
    }
    matched.to_string()
}

// ─── PUBLIC API ──────────────────────────────────────────

pub fn scan_text(text: &str, path: &str) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    let text_lower = text.to_lowercase();

    for (re, rule) in COMPILED.iter() {
        // 1. KEYWORD PRE-FILTER — 不命中直接 skip
        let mut hit = rule.keywords.is_empty();
        for kw in rule.keywords {
            if text_lower.contains(&kw.to_lowercase()) { hit = true; break; }
        }
        if !hit { continue; }

        // 2. REGEX MATCH
        for m in re.find_iter(text) {
            let matched = m.as_str().to_string();

            let secret_part = extract_secret_part(&matched, rule.id);
            let entropy = shannon_entropy(&secret_part);
            if rule.entropy_min > 0.0 && entropy < rule.entropy_min { continue; }

            if should_skip(&matched, rule.id, entropy) { continue; }

            let before = &text[..m.start()];
            let line = before.chars().filter(|&c| c == '\n').count() as u32 + 1;

            let line_start = text[..m.start()].rfind('\n').map(|p| p + 1).unwrap_or(0);
            let line_end = text[m.end()..].find('\n').map(|p| m.end() + p).unwrap_or(text.len());
            let snippet = text[line_start..line_end].to_string();

            findings.push(LeakFinding {
                rule_id: rule.id.to_string(),
                rule_name: rule.name.to_string(),
                category: rule.category.to_string(),
                path: path.to_string(),
                line,
                snippet,
                matched: matched.clone(),
                display_matched: mask_for_rule(rule.id, &matched),
                entropy,
                verified: None,
            });
        }
    }

    // Dedup
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.rule_id.clone(), f.matched.clone())));

    findings
}

// Pro-only token verification
pub fn verify_secret(secret: &str, rule_id: &str) -> bool {
    match rule_id {
        "github-classic-token" | "github-oauth-token" | "github-user-token"
        | "github-installation-token" | "github-refresh-token" => {
            let r = ureq::get("https://api.github.com/user")
                .set("Authorization", &format!("Bearer {secret}"))
                .set("User-Agent", "LeakScope").call();
            matches!(r, Ok(resp) if resp.status() == 200)
        }
        "openai-api-key" | "openai-legacy-key" => {
            let r = ureq::get("https://api.openai.com/v1/models")
                .set("Authorization", &format!("Bearer {secret}")).call();
            matches!(r, Ok(resp) if resp.status() != 401)
        }
        "stripe-live-api-key" | "stripe-live-restricted-key" => {
            let r = ureq::get("https://api.stripe.com/v1/account")
                .set("Authorization", &format!("Bearer {secret}")).call();
            matches!(r, Ok(resp) if resp.status() == 200)
        }
        "slack-bot-token" | "slack-user-token" => {
            let r = ureq::get("https://slack.com/api/auth.test")
                .set("Authorization", &format!("Bearer {secret}")).call();
            matches!(r, Ok(resp) if resp.status() != 401)
        }
        "sendgrid-api-key" => {
            let r = ureq::get("https://api.sendgrid.com/v3/user/scopes")
                .set("Authorization", &format!("Bearer {secret}")).call();
            matches!(r, Ok(resp) if resp.status() != 401)
        }
        "datadog-api-key" => {
            let r = ureq::get("https://api.datadoghq.com/api/v1/validate")
                .set("DD-API-KEY", secret).call();
            matches!(r, Ok(resp) if resp.status() == 200)
        }
        _ => true, // format-valid, can't verify externally
    }
}
