// ─── Git History Scanner (Pro) ──────────────────────────
// Partial clone + git log -p → scan added lines for secrets.
// Much cheaper than full clone (only downloads commit metadata + blobs we touch).

use crate::LeakFinding;
use std::process::Command;

#[derive(Clone)]
pub struct CommitFinding {
    pub commit_hash: String,
    pub commit_author: String,
    pub commit_date: String,
    pub message: String,
    pub file_path: String,
    pub line_number: u32,
    pub finding: LeakFinding,
}

/// Check if `git` binary is available on PATH.
pub fn git_available() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// Scan a repo's git history for secrets introduced in commits.
///
/// Returns all findings with commit metadata. Runs on blocking pool (spawns git subprocess).
pub fn scan_repo_history(
    token: &str,
    owner: &str,
    repo: &str,
    max_commits: u32,
) -> Result<Vec<CommitFinding>, String> {
    if !git_available() {
        return Err("git not found on PATH — please install git CLI".into());
    }

    // Build auth URL — embed PAT for private repos (GitHub supports this)
    let remote = format!(
        "https://x-access-token:{token}@github.com/{owner}/{repo}.git",
        token = token,
        owner = owner,
        repo = repo
    );

    // Temp dir — system temp + unique dir
    let tmp = std::env::temp_dir().join(format!("leakscope-history-{owner}-{repo}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("mkdir: {e}"))?;

    // 1. Partial clone — no blobs by default, only metadata
    //    --filter=blob:none means we don't download any file contents yet
    let clone_status = Command::new("git")
        .args(["clone", "--filter=blob:none", "--no-checkout", "--quiet",
               "--depth", "500",
               &remote, tmp.to_str().ok_or("bad path")?])
        .status()
        .map_err(|e| format!("git clone spawn: {e}"))?;
    if !clone_status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("git clone failed — check token scope or repo access".into());
    }

    // 2. For each branch, walk commits collecting diff patches
    //    We use `git log -p -U0` to get zero-context diffs (only changed lines)
    let max = max_commits.to_string();
    let log_output = Command::new("git")
        .current_dir(&tmp)
        .args(["log", "--all", "--no-merges", "-p", "-U0",
               "--format=---COMMIT--- %H%n%an <%ae>%n%ad%n%s",
               "--date=short",
               "-n", &max])
        .output()
        .map_err(|e| format!("git log spawn: {e}"))?;

    if !log_output.status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("git log failed".into());
    }

    let log_text = String::from_utf8_lossy(&log_output.stdout);
    let findings = parse_and_scan(&log_text);

    // 3. Cleanup
    let _ = std::fs::remove_dir_all(&tmp);

    Ok(findings)
}

fn parse_and_scan(log_text: &str) -> Vec<CommitFinding> {
    let mut results: Vec<CommitFinding> = Vec::new();
    let mut current_commit: Option<CommitMeta> = None;
    let mut current_file: Option<String> = None;
    let mut new_line_number: u32 = 0;

    for raw_line in log_text.lines() {
        // ── Commit header ──
        if raw_line.starts_with("---COMMIT--- ") {
            current_commit = Some(CommitMeta {
                hash: raw_line["---COMMIT--- ".len()..].to_string(),
                author: String::new(),
                date: String::new(),
                message: String::new(),
            });
            current_file = None;
            new_line_number = 0;
            continue;
        }

        // Commit meta lines follow after ---COMMIT---
        if let Some(commit) = current_commit.as_mut() {
            if commit.author.is_empty() && raw_line.contains(" <") {
                commit.author = raw_line.to_string();
                continue;
            }
            if commit.date.is_empty() && !raw_line.is_empty() && !raw_line.starts_with(' ') && !raw_line.starts_with(':') {
                // First non-empty non-address line after author = date
                if raw_line.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    commit.date = raw_line.to_string();
                    continue;
                }
            }
            if commit.message.is_empty() && !raw_line.is_empty()
                && !raw_line.contains(" <")
                && !raw_line.chars().next().map_or(false, |c| c.is_ascii_digit())
                && !raw_line.starts_with("diff --git") {
                commit.message = raw_line.to_string();
                continue;
            }
        }

        // ── File header in diff ──
        if raw_line.starts_with("diff --git ") {
            // diff --git a/path/to/file b/path/to/file
            if let Some(path_part) = raw_line.splitn(3, ' ').nth(2) {
                let path = path_part[2..].to_string(); // strip "b/"
                current_file = Some(path);
            }
            new_line_number = 0;
            continue;
        }

        // ── Hunk header — resets line counters ──
        if raw_line.starts_with("@@ ") {
            // @@ -oldStart,oldLen +newStart,newLen @@
            if let Some(plus_start) = raw_line.split('+').nth(1) {
                if let Some(num) = plus_start.split(',').next() {
                    new_line_number = num.parse().unwrap_or(0);
                }
            }
            continue;
        }

        // ── Added line in diff ──
        if let Some(file) = current_file.as_ref() {
            if raw_line.starts_with('+') && !raw_line.starts_with("+++") {
                let added_content = &raw_line[1..]; // strip leading '+'
                let line_no = new_line_number;
                new_line_number += 1;

                // Scan this single line
                let found = crate::scanner::scan_text(added_content, file);
                for finding in found {
                    results.push(CommitFinding {
                        commit_hash: current_commit.as_ref().map(|c| c.hash.clone()).unwrap_or_default(),
                        commit_author: current_commit.as_ref().map(|c| c.author.clone()).unwrap_or_default(),
                        commit_date: current_commit.as_ref().map(|c| c.date.clone()).unwrap_or_default(),
                        message: current_commit.as_ref().map(|c| c.message.clone()).unwrap_or_default(),
                        file_path: file.clone(),
                        line_number: line_no,
                        finding,
                    });
                }
            } else if raw_line.starts_with('-') && !raw_line.starts_with("---") {
                // Removed line — doesn't advance new_line_number
                continue;
            } else {
                // Context line (shouldn't exist with -U0, but safety)
                new_line_number += 1;
            }
        }
    }

    // Deduplicate — same matched value in same file
    let mut seen = std::collections::HashSet::new();
    results.retain(|cf| {
        let key = format!("{}:{}:{}", cf.file_path, cf.line_number, cf.finding.display_matched);
        seen.insert(key)
    });

    results
}

#[derive(Clone)]
struct CommitMeta {
    hash: String,
    author: String,
    date: String,
    message: String,
}
