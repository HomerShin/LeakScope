// License activation — shared protocol with Cloudflare Worker
// Runtime-only: no #[cfg(feature)] gating.
// Community vs Pro is determined by whether a valid license.json exists.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const LICENSE_SERVER: &str = "https://leakscope-license.805998855.workers.dev";

#[derive(Serialize, Deserialize, Clone, Default)]
struct LicenseFile {
    email: String,
    key: String,
    plan: String,
    verified_at: Option<i64>,
    local_token: Option<String>,
    grace_seconds: i64,
}

fn license_path() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join("LeakScope").join("license.json"))
}

#[derive(Serialize, Clone)]
pub struct LicenseStatus {
    pub valid: bool,
    pub plan: String,
    pub email: Option<String>,
    pub expires_at: Option<i64>,
    pub message: String,
}

fn read_license_file() -> Option<LicenseFile> {
    let path = license_path()?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => { eprintln!("[license] read error: {}", e); return None; }
    };
    // Strip UTF-8 BOM if present (PowerShell Set-Content adds it)
    let raw = raw.trim_start_matches('\u{FEFF}');
    eprintln!("[license] raw json: {}", raw);
    match serde_json::from_str::<LicenseFile>(&raw) {
        Ok(lic) => { eprintln!("[license] parsed: plan={}, token={:?}, verified={:?}", lic.plan, lic.local_token.as_ref().map(|t| t.as_str()), lic.verified_at); Some(lic) }
        Err(e) => { eprintln!("[license] parse error: {}", e); None }
    }
}

pub fn get_license() -> LicenseStatus {
    let Some(lic) = read_license_file() else {
        // No license file → Community edition
        return LicenseStatus {
            valid: true, plan: "community".into(),
            email: None, expires_at: None,
            message: "Community edition".into(),
        };
    };

    let Some(token) = lic.local_token.as_ref() else {
        return LicenseStatus { valid: false, plan: "pro".into(), email: Some(lic.email), expires_at: None,
            message: "No local token — please re-activate".into() };
    };
    if token.is_empty() {
        return LicenseStatus { valid: false, plan: "pro".into(), email: Some(lic.email), expires_at: None,
            message: "No local token — please re-activate".into() };
    }

    let now = chrono::Utc::now().timestamp();
    let grace_expired = lic.verified_at.map_or(true, |v| now - v > lic.grace_seconds);
    LicenseStatus {
        valid: !grace_expired,
        plan: lic.plan.clone(),
        email: Some(lic.email.clone()),
        expires_at: lic.verified_at.map(|v| v + lic.grace_seconds),
        message: if grace_expired { "Offline grace expired — re-activate".into() } else { "Pro license OK ✓".into() },
    }
}

/// Returns true when a valid Pro license is present (local token + within grace)
pub fn is_pro() -> bool {
    let s = get_license();
    eprintln!("[license] is_pro check: valid={}, plan={}, message={}", s.valid, s.plan, s.message);
    s.valid && s.plan == "pro"
}

pub fn activate(email: &str, key: &str) -> Result<LicenseStatus, String> {
    let url = format!("{}/api/license/verify", LICENSE_SERVER);
    let body = serde_json::json!({ "email": email, "key": key });
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("Network error: {e}"))?;

    let resp_json: serde_json::Value = serde_json::from_str(
        &resp.into_string().unwrap_or_default()
    ).map_err(|e| format!("Bad response: {e}"))?;

    let valid = resp_json["valid"].as_bool().unwrap_or(false);
    let plan = resp_json["plan"].as_str().unwrap_or("pro").to_string();

    if !valid {
        return Err(resp_json["message"].as_str().unwrap_or("License key invalid").to_string());
    }

    let now = chrono::Utc::now().timestamp();
    let token = resp_json["token"].as_str().map(|s| s.to_string()).unwrap_or_else(|| "verified".into());

    let lic = LicenseFile {
        email: email.to_string(),
        key: key.to_string(),
        plan: plan.clone(),
        verified_at: Some(now),
        local_token: Some(token),
        grace_seconds: 7 * 24 * 3600,
    };

    if let Some(path) = license_path() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&lic).unwrap_or_default());
    }

    Ok(LicenseStatus {
        valid: true, plan, email: Some(email.to_string()),
        expires_at: Some(now + lic.grace_seconds),
        message: "License activated ✓".into(),
    })
}

pub fn clear() -> Result<(), String> {
    if let Some(path) = license_path() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}
