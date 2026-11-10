// GitHub OAuth device flow + REST API client
// No redirect URI needed — perfect for desktop apps.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const GITHUB_DEVICE_URL: &str = "https://github.com/login/device/code";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_API: &str = "https://api.github.com";

// OAuth App — create one at https://github.com/settings/developers
// Authorization callback URL: http://localhost (we use device flow so it's ignored)
const GITHUB_CLIENT_ID: &str = "Iv1.LeakScopeDeviceFlow"; // TODO: replace with real client ID
const GITHUB_SCOPES: &str = "repo read:org read:user"; // repo = access private repos

fn token_path() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join("LeakScope").join("github_token.txt"))
}

pub fn save_token(token: &str) -> Result<(), String> {
    let path = token_path().ok_or("Cannot resolve app data dir")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, token).map_err(|e| e.to_string())
}

pub fn load_token() -> Option<String> {
    let path = token_path()?;
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

pub fn clear_token() -> Result<(), String> {
    if let Some(path) = token_path() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

// ─── Device Flow ──────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceFlowResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u32,
    pub interval: u32,
}

pub fn start_device_flow() -> Result<DeviceFlowResponse, String> {
    let body = format!(
        "client_id={}&scope={}",
        GITHUB_CLIENT_ID, GITHUB_SCOPES
    );
    let resp = ureq::post(GITHUB_DEVICE_URL)
        .set("Accept", "application/json")
        .send_string(&body)
        .map_err(|e| format!("OAuth start failed: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(
        &resp.into_string().unwrap_or_default()
    ).map_err(|e| format!("Bad OAuth response: {e}"))?;

    Ok(DeviceFlowResponse {
        device_code: json["device_code"].as_str().ok_or("no device_code")?.into(),
        user_code: json["user_code"].as_str().ok_or("no user_code")?.into(),
        verification_uri: json["verification_uri"].as_str().ok_or("no verification_uri")?.into(),
        expires_in: json["expires_in"].as_u64().unwrap_or(900) as u32,
        interval: json["interval"].as_u64().unwrap_or(5) as u32,
    })
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

pub async fn poll_device_token(device_code: &str) -> Result<TokenResponse, String> {
    // Poll up to 3 min — caller should show progress
    for _ in 0..36 {
        let body = format!(
            "client_id={}&device_code={}&grant_type=urn:ietf:params:oauth:grant-type:device_code",
            GITHUB_CLIENT_ID, device_code
        );
        // Spawn blocking — ureq is sync, don't block the async runtime
        let body_clone = body.clone();
        let json = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let resp = ureq::post(GITHUB_TOKEN_URL)
                .set("Accept", "application/json")
                .send_string(&body_clone)
                .map_err(|e| format!("poll error: {e}"))?;
            Ok(serde_json::from_str(&resp.into_string().unwrap_or_default()).unwrap_or_default())
        }).await.map_err(|e| format!("poll join error: {e}"))??;

        if let Some(token) = json["access_token"].as_str() {
            return Ok(TokenResponse {
                access_token: token.to_string(),
                token_type: json["token_type"].as_str().unwrap_or("bearer").to_string(),
                scope: json["scope"].as_str().unwrap_or("").to_string(),
            });
        }
        let err = json["error"].as_str().unwrap_or("");
        if err == "access_denied" {
            return Err("Authorization denied by user".into());
        }
        if err == "slow_down" {
            // GitHub 要求加长间隔
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            continue;
        }
        // authorization_pending → keep polling (async sleep)
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    Err("Timed out waiting for authorization — please try again".into())
}

// ─── Helpers ──────────────────────────────────────────

/// Run a sync ureq call on the blocking thread pool.
async fn gh_get(raw_url: String, token: String, accept: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        ureq::get(&raw_url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Accept", &accept)
            .set("User-Agent", "LeakScope")
            .call()
            .map_err(|e| format!("GH API error: {e}"))
            .and_then(|r| r.into_string().map_err(|e| format!("read error: {e}")))
    })
    .await
    .map_err(|e| format!("join error: {e}"))?
}

// ─── GitHub API ──────────────────────────────────────

#[derive(Deserialize, Debug)]
struct GhRepo {
    name: String,
    full_name: String,
    description: Option<String>,
    private: bool,
    default_branch: String,
    html_url: String,
    stargazers_count: u32,
    language: Option<String>,
}

pub async fn fetch_user_repos(token: &str) -> Result<Vec<crate::Repo>, String> {
    let mut out = Vec::new();
    let mut page = 1u32;
    loop {
        let url = format!(
            "{}/user/repos?per_page=100&page={}&visibility=all&affiliation=owner,collaborator,organization_member",
            GITHUB_API, page
        );
        let body = gh_get(url, token.to_string(), "application/vnd.github+json".into()).await?;
        let repos: Vec<GhRepo> = serde_json::from_str(&body).unwrap_or_default();
        if repos.is_empty() { break; }
        for r in repos {
            out.push(crate::Repo {
                name: r.name,
                full_name: r.full_name,
                description: r.description,
                is_private: r.private,
                default_branch: r.default_branch,
                url: r.html_url,
                stars: r.stargazers_count,
                language: r.language,
            });
        }
        page += 1;
        if page > 10 { break; } // safety
    }
    Ok(out)
}

#[derive(Deserialize, Debug)]
struct GhTreeItem {
    path: String,
    #[allow(dead_code)]
    mode: String,
    #[allow(dead_code)]
    sha: String,
    size: Option<u64>,
    #[allow(dead_code)]
    url: String,
    #[serde(rename = "type")]
    item_type: String,
}

#[derive(Serialize, Clone)]
pub struct RepoFile {
    pub path: String,
    pub size: u64,
    pub is_file: bool,
}

pub async fn fetch_repo_tree(
    token: &str, owner: &str, repo: &str, branch: &str,
) -> Result<Vec<RepoFile>, String> {
    let url = format!(
        "{}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
        GITHUB_API
    );
    let body = gh_get(url, token.to_string(), "application/vnd.github+json".into()).await?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("tree parse: {e}"))?;

    let mut out = Vec::new();
    let items = json["tree"].as_array().cloned().unwrap_or_default();
    for item in items {
        let ti: GhTreeItem = serde_json::from_value(item).unwrap_or_else(|_| {
            GhTreeItem { path: String::new(), mode: String::new(), sha: String::new(),
                size: None, url: String::new(), item_type: String::new() }
        });
        if ti.item_type == "blob" {
            let size = ti.size.unwrap_or(0);
            // Skip files > 5MB — binary or too large for regex scan
            if size > 5 * 1024 * 1024 { continue; }
            // Skip common binary extensions
            let lower = ti.path.to_lowercase();
            if matches!(lower.as_str(),
                p if p.ends_with(".png") || p.ends_with(".jpg") || p.ends_with(".jpeg")
                   || p.ends_with(".gif") || p.ends_with(".pdf") || p.ends_with(".zip")
                   || p.ends_with(".gz") || p.ends_with(".tar") || p.ends_with(".bin")
                   || p.ends_with(".woff") || p.ends_with(".ico") || p.ends_with(".svg")
                   || p.ends_with(".lock") || p.ends_with(".log")
            ) { continue; }
            out.push(RepoFile { path: ti.path, size, is_file: true });
        }
    }
    Ok(out)
}

pub async fn fetch_file_content(
    token: &str, owner: &str, repo: &str, path: &str,
) -> Result<String, String> {
    let url = format!(
        "{}/repos/{owner}/{repo}/contents/{}",
        GITHUB_API,
        path.replace(' ', "%20")
    );
    gh_get(url, token.to_string(), "application/vnd.github.raw+json".into()).await
}
