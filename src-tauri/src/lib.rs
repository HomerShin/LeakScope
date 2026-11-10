// LeakScope Rust backend — lib.rs entry point
// All features compiled in; Community vs Pro determined at runtime by license file.
mod github;
mod scanner;
mod license;
mod git;

use serde::Serialize;

// ────────────────────────────────────────────────────
// Shared types
// ────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct AppInfo {
    pub is_pro: bool,
    pub version: String,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        is_pro: license::is_pro(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

// ────────────────────────────────────────────────────
// GitHub OAuth — device flow (no redirect needed)
// ────────────────────────────────────────────────────

#[tauri::command]
fn oauth_start() -> Result<github::DeviceFlowResponse, String> {
    github::start_device_flow()
}

#[tauri::command]
async fn oauth_poll(code: String) -> Result<github::TokenResponse, String> {
    github::poll_device_token(&code).await
}

#[tauri::command]
fn oauth_save(token: String) -> Result<(), String> {
    github::save_token(&token)
}

#[tauri::command]
fn oauth_load() -> Option<String> {
    github::load_token()
}

#[tauri::command]
fn oauth_clear() -> Result<(), String> {
    github::clear_token()
}

// ────────────────────────────────────────────────────
// GitHub API — repos + file content
// ────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct Repo {
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub is_private: bool,
    pub default_branch: String,
    pub url: String,
    pub stars: u32,
    pub language: Option<String>,
}

#[tauri::command]
async fn list_repos(token: String) -> Result<Vec<Repo>, String> {
    github::fetch_user_repos(&token).await
}

#[tauri::command]
async fn get_repo_files(token: String, owner: String, repo: String, branch: String) -> Result<Vec<github::RepoFile>, String> {
    github::fetch_repo_tree(&token, &owner, &repo, &branch).await
}

#[tauri::command]
async fn get_file_content(token: String, owner: String, repo: String, path: String) -> Result<String, String> {
    github::fetch_file_content(&token, &owner, &repo, &path).await
}

// ────────────────────────────────────────────────────
// Scanner
// ────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct LeakFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub path: String,
    pub line: u32,
    pub snippet: String,
    pub matched: String,         // raw value — Pro verify uses this
    pub display_matched: String,  // masked value — UI shows this
    pub entropy: f64,
    pub verified: Option<bool>,
}

#[tauri::command]
fn scan_text(text: String, path: String) -> Vec<LeakFinding> {
    scanner::scan_text(&text, &path)
}

#[tauri::command]
async fn verify_token(matched: String, rule_id: String) -> Result<bool, String> {
    if !license::is_pro() {
        return Err("Token verification requires a Pro license".into());
    }
    let ok = tokio::task::spawn_blocking(move || scanner::verify_secret(&matched, &rule_id))
        .await
        .map_err(|e| format!("verify join error: {e}"))?;
    Ok(ok)
}

// ────────────────────────────────────────────────────
// Git history scan (Pro-only at runtime)
// ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HistoryFinding {
    pub commit_hash: String,
    pub commit_author: String,
    pub commit_date: String,
    pub commit_message: String,
    pub file_path: String,
    pub line_number: u32,
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub entropy: f64,
    pub display_matched: String,
}

#[tauri::command]
async fn scan_repo_history(
    token: String,
    owner: String,
    repo: String,
    max_commits: Option<u32>,
) -> Result<Vec<HistoryFinding>, String> {
    if !license::is_pro() {
        return Err("Git history scan requires a Pro license".into());
    }
    let max = max_commits.unwrap_or(500);
    let owner_clone = owner.clone();
    let repo_clone = repo.clone();
    let results = tokio::task::spawn_blocking(move || {
        git::scan_repo_history(&token, &owner_clone, &repo_clone, max)
    })
    .await
    .map_err(|e| format!("history join error: {e}"))??;

    Ok(results.into_iter().map(|cf| HistoryFinding {
        commit_hash: cf.commit_hash,
        commit_author: cf.commit_author,
        commit_date: cf.commit_date,
        commit_message: cf.message,
        file_path: cf.file_path,
        line_number: cf.line_number,
        rule_id: cf.finding.rule_id,
        rule_name: cf.finding.rule_name,
        category: cf.finding.category,
        entropy: cf.finding.entropy,
        display_matched: cf.finding.display_matched,
    }).collect())
}

// ────────────────────────────────────────────────────
// Revocation URL map — rule_id → where to go revoke
// ────────────────────────────────────────────────────

#[tauri::command]
fn get_revoke_url(rule_id: String) -> Option<String> {
    let map: &[(&str, &str)] = &[
        // Cloud
        ("aws-access-token", "https://console.aws.amazon.com/iam/home#/security_credentials"),
        ("aws-secret-access-key", "https://console.aws.amazon.com/iam/home#/security_credentials"),
        ("aws-session-token", "https://console.aws.amazon.com/iam/home#/security_credentials"),
        ("gcp-api-key", "https://console.cloud.google.com/apis/credentials"),
        ("gcp-service-account", "https://console.cloud.google.com/iam-admin/serviceaccounts"),
        ("azure-storage-key", "https://portal.azure.com/#blade/Microsoft_Azure_Storage/KeyValueBlade"),
        ("azure-ad-client-secret", "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps"),
        ("digitalocean-api-token", "https://cloud.digitalocean.com/account/api/tokens"),
        ("cloudflare-api-token", "https://dash.cloudflare.com/profile/api-tokens"),

        // Payment
        ("stripe-live-api-key", "https://dashboard.stripe.com/apikeys"),
        ("stripe-live-restricted-key", "https://dashboard.stripe.com/apikeys"),
        ("stripe-test-api-key", "https://dashboard.stripe.com/apikeys/test"),
        ("square-access-token", "https://developer.squareup.com/apps"),

        // AI
        ("openai-api-key", "https://platform.openai.com/api-keys"),
        ("openai-legacy-key", "https://platform.openai.com/api-keys"),
        ("anthropic-api-key", "https://console.anthropic.com/settings/keys"),
        ("cohere-api-key", "https://dashboard.cohere.com/api-keys"),
        ("perplexity-api-key", "https://www.perplexity.ai/settings/api"),
        ("groq-api-key", "https://console.groq.com/keys"),
        ("mistral-api-key", "https://console.mistral.ai/api-keys/"),

        // Dev platforms
        ("github-classic-token", "https://github.com/settings/tokens"),
        ("github-oauth-token", "https://github.com/settings/tokens"),
        ("github-user-token", "https://github.com/settings/apps"),
        ("github-installation-token", "https://github.com/settings/apps"),
        ("github-refresh-token", "https://github.com/settings/tokens"),
        ("gitlab-pat", "https://gitlab.com/-/user_settings/personal_access_tokens"),
        ("gitlab-pipeline-token", "https://gitlab.com/-/user_settings/personal_access_tokens"),
        ("npm-access-token", "https://www.npmjs.com/"),
        ("pypi-api-token", "https://pypi.org/manage/account/token/"),

        // Communication
        ("slack-bot-token", "https://api.slack.com/apps"),
        ("slack-user-token", "https://api.slack.com/apps"),
        ("slack-webhook-url", "https://api.slack.com/apps"),
        ("discord-bot-token", "https://discord.com/developers/applications"),
        ("discord-webhook-url", "https://discord.com/developers/applications"),
        ("telegram-bot-token", "https://t.me/BotFather"),
        ("twilio-account-sid", "https://console.twilio.com/"),
        ("sendgrid-api-key", "https://app.sendgrid.com/settings/api_keys"),
        ("mailgun-api-key", "https://app.mailgun.com/app/account/security/api_keys"),

        // Database / Misc
        ("mongodb-uri", "https://cloud.mongodb.com/"),
        ("datadog-api-key", "https://app.datadoghq.com/settings/organization/api_keys"),
        ("new-relic-api-key", "https://one.newrelic.com/api-keys"),
        ("dynatrace-api-token", "https://<your-dynatrace>.live.dynatrace.com/ui/access-tokens"),
        ("grafana-api-key", "https://grafana.com/profile/api-keys"),
        ("sentry-auth-token", "https://sentry.io/settings/account/auth-tokens/"),
        ("hashicorp-vault-token", "https://developer.hashicorp.com/vault/docs/commands/auth"),
        ("docker-hub-token", "https://hub.docker.com/settings/security"),
    ];
    map.iter().find(|(id, _)| *id == rule_id).map(|(_, url)| url.to_string())
}

// ────────────────────────────────────────────────────
// License activation
// ────────────────────────────────────────────────────

#[tauri::command]
fn get_license() -> license::LicenseStatus {
    license::get_license()
}

#[tauri::command]
fn activate_license(email: String, key: String) -> Result<license::LicenseStatus, String> {
    license::activate(&email, &key)
}

#[tauri::command]
fn clear_license() -> Result<(), String> {
    license::clear()
}

// ────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            app_info,
            oauth_start, oauth_poll, oauth_save, oauth_load, oauth_clear,
            list_repos, get_repo_files, get_file_content,
            scan_text, verify_token, get_revoke_url, scan_repo_history,
            get_license, activate_license, clear_license,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
