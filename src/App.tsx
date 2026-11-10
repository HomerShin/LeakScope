import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useState, useEffect, useRef } from "react";

// ─── Types ────────────────────────────────────────────

type Repo = {
  name: string;
  full_name: string;
  description: string | null;
  is_private: boolean;
  default_branch: string;
  url: string;
  stars: number;
  language: string | null;
};

type LeakFinding = {
  rule_id: string;
  rule_name: string;
  category: string;
  path: string;
  line: number;
  snippet: string;
  matched: string;           // raw — for verify API
  display_matched: string;   // masked — for UI display
  entropy: number;
  verified: boolean | null;
};

type DeviceFlow = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
};

// ─── Main App ──────────────────────────────────────────

export default function App() {
  const [step, setStep] = useState<"connect" | "repos" | "scanning" | "results">("connect");
  const [token, setToken] = useState<string | null>(null);
  const [isPro, setIsPro] = useState(false);
  const [appVersion, setAppVersion] = useState("0.0.0");
  const [scanMode, setScanMode] = useState<"head" | "history">("head");
  const [isMaximized, setIsMaximized] = useState(false);
  const scanCancelled = useRef(false);

  // Window controls
  const win = getCurrentWindow();
  const handleMinimize = async () => {
    try { await win.minimize(); } catch (e) { console.warn("minimize failed:", e); alert("Minimize failed: " + e); }
  };
  const handleToggleMax = async () => {
    try {
      await win.toggleMaximize();
      setIsMaximized(await win.isMaximized());
    } catch (e) { console.warn("toggleMax failed:", e); alert("Maximize failed: " + e); }
  };
  const handleClose = async () => {
    try { await win.close(); } catch (e) { console.warn("close failed:", e); alert("Close failed: " + e); }
  };

  // Sync maximized state on mount
  useEffect(() => { win.isMaximized().then(setIsMaximized).catch(() => {}); }, []);

  // Global keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Don't hijack inputs
      const target = e.target as HTMLElement;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) return;

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "r") {
        e.preventDefault();
        if (step === "results") startScan();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "w") {
        e.preventDefault();
        win.close();
      }
      if (e.key === "Escape") {
        if (step === "results") setStep("repos");
        if (step === "repos") setStep("connect");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [step]);

  // License state
  const [licenseValid, setLicenseValid] = useState(true);
  const [licenseEmail, setLicenseEmail] = useState<string | null>(null);
  const [showActivation, setShowActivation] = useState(false);
  const [actEmail, setActEmail] = useState("");
  const [actKey, setActKey] = useState("");
  const [actBusy, setActBusy] = useState(false);
  const [actMsg, setActMsg] = useState("");

  // Repo state
  const [repos, setRepos] = useState<Repo[]>([]);
  const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");

  // Scan state
  const [scanProgress, setScanProgress] = useState({ repo: "", file: "", done: 0, total: 0 });
  const [findings, setFindings] = useState<LeakFinding[]>([]);
  const [scanStats, setScanStats] = useState<{ repos: number; files: number; seconds: number; mode: string } | null>(null);

  // First boot — check license + token
  useEffect(() => {
    invoke<{ is_pro: boolean; version: string }>("app_info").then(
      (info) => { setIsPro(info.is_pro); setAppVersion(info.version); },
      () => {}
    );
    invoke<{ valid: boolean; plan: string; email: string | null; expires_at: number | null; message: string }>("get_license").then(
      (lic) => {
        setLicenseValid(lic.valid);
        setLicenseEmail(lic.email);
        if (lic.plan === "pro" && !lic.valid) setShowActivation(true);
      },
      () => {}
    );
    invoke<string | null>("oauth_load").then(
      (t) => { if (t) { setToken(t); setStep("repos"); } },
      () => {}
    );
  }, []);

  // ─── OAuth Flow ────────────────────────────────────

  const [oauthBusy, setOauthBusy] = useState(false);
  const startOAuth = async () => {
    setOauthBusy(true);
    try {
      const flow = await invoke<DeviceFlow>("oauth_start");
      // Open verification URL
      await openUrl(flow.verification_uri);
      alert("Device code: " + flow.user_code + "\n\nPlease enter this code in the browser to authorize. Waiting...");
      // Poll
      const tokenResp = await invoke<{ access_token: string; token_type: string; scope: string }>(
        "oauth_poll", { code: flow.device_code }
      );
      await invoke("oauth_save", { token: tokenResp.access_token });
      setToken(tokenResp.access_token);
      setStep("repos");
      await loadRepos(tokenResp.access_token);
    } catch (err: any) {
      alert("GitHub OAuth failed: " + (err?.toString?.() || String(err)) +
        "\n\nTip: GitHub OAuth App Client ID is still a placeholder. Use the 'paste PAT directly' option instead.");
    } finally {
      setOauthBusy(false);
    }
  };

  const handleTokenPaste = async (raw: string) => {
    try {
      await invoke("oauth_save", { token: raw });
      setToken(raw);
      setStep("repos");
      await loadRepos(raw);
    } catch (err) {
      alert("Failed to use token: " + err);
    }
  };

  const disconnect = async () => {
    await invoke("oauth_clear");
    setToken(null);
    setRepos([]);
    setSelectedRepos(new Set());
    setFindings([]);
    setStep("connect");
  };

  const loadRepos = async (t: string) => {
    const list = await invoke<Repo[]>("list_repos", { token: t });
    setRepos(list);
    // Default select first 3
    const sel = new Set(list.slice(0, 3).map((r) => r.full_name));
    setSelectedRepos(sel);
  };

  const toggleRepo = (fullName: string) => {
    const next = new Set(selectedRepos);
    if (next.has(fullName)) next.delete(fullName);
    else next.add(fullName);
    setSelectedRepos(next);
  };

  const toggleAll = () => {
    if (selectedRepos.size === repos.length) setSelectedRepos(new Set());
    else setSelectedRepos(new Set(repos.map((r) => r.full_name)));
  };

  // ─── Scan ──────────────────────────────────────────

  const startScan = async () => {
    if (!token || selectedRepos.size === 0) return;
    scanCancelled.current = false;
    setStep("scanning");
    setFindings([]);
    setScanStats(null);
    const scanStart = Date.now();
    const mode = scanMode === "history" ? "git history" : "HEAD (current)";

    // History mode (Pro — git clone + log -p)
    if (scanMode === "history") {
      const all: LeakFinding[] = [];
      let reposScanned = 0;
      for (const fullName of selectedRepos) {
        if (scanCancelled.current) break;
        const [owner, repo] = fullName.split("/");
        setScanProgress({ repo: fullName, file: "Git partial clone...", done: 0, total: 0 });
        try {
          const raw = await invoke<any[]>("scan_repo_history", {
            token, owner, repo, maxCommits: 500,
          });
          setScanProgress({ repo: fullName, file: `Parsed ${raw.length} history findings`, done: raw.length, total: raw.length });
          for (const hf of raw) {
            all.push({
              rule_id: hf.rule_id,
              rule_name: hf.rule_name,
              category: hf.category,
              path: `${hf.commit_hash.slice(0, 7)} · ${hf.file_path}`,
              line: hf.line_number,
              snippet: `${hf.commit_author} · ${hf.commit_date}\n${hf.commit_message}\n\n${hf.file_path}:${hf.line_number}`,
              matched: "",
              display_matched: hf.display_matched,
              entropy: hf.entropy,
              verified: null,
            });
          }
          reposScanned++;
        } catch (e: any) {
          const msg = e?.toString?.() || String(e);
          if (msg.includes("git not found")) {
            alert("Git history scan requires git CLI.\n\nDownload from https://git-scm.com/ or switch to HEAD mode.");
          } else {
            console.warn(`History scan ${fullName} failed:`, e);
          }
        }
      }
      const elapsed = Math.max(1, Math.round((Date.now() - scanStart) / 1000));
      setFindings(all);
      setScanStats({ repos: reposScanned, files: 0, seconds: elapsed, mode });
      setStep("results");
      return;
    }

    // HEAD mode (Community — GitHub API)
    const all: LeakFinding[] = [];
    let filesScanned = 0;
    let totalFiles = 0;
    let reposScanned = 0;

    for (const fullName of selectedRepos) {
      if (scanCancelled.current) break;
      const [owner, repo] = fullName.split("/");
      const defaultBranch = repos.find((r) => r.full_name === fullName)?.default_branch ?? "main";
      setScanProgress({ repo: fullName, file: "Loading tree...", done: filesScanned, total: 0 });
      try {
        const files = await invoke<{ path: string; size: number; is_file: boolean }[]>(
          "get_repo_files", { token, owner, repo, branch: defaultBranch }
        );
        totalFiles += files.length;
        for (const f of files) {
          if (scanCancelled.current) break;
          setScanProgress({ repo: fullName, file: f.path, done: filesScanned, total: totalFiles });
          try {
            const content = await invoke<string>("get_file_content", {
              token, owner, repo, path: f.path,
            });
            const leaks = await invoke<LeakFinding[]>("scan_text", { text: content, path: `${fullName}/${f.path}` });
            all.push(...leaks);
          } catch (e) { /* ignore per-file errors */ }
          filesScanned++;
        }
        reposScanned++;
      } catch (e) {
        console.warn(`Repo ${fullName} scan failed:`, e);
      }
    }

    const elapsed = Math.max(1, Math.round((Date.now() - scanStart) / 1000));
    setFindings(all);
    setScanStats({ repos: reposScanned, files: filesScanned, seconds: elapsed, mode });
    setStep("results");
  };

  const filteredRepos = repos.filter((r) =>
    r.full_name.toLowerCase().includes(filter.toLowerCase()) ||
    (r.description || "").toLowerCase().includes(filter.toLowerCase())
  );

  // ─── Activation ────────────────────────────────────

  const handleActivate = async () => {
    if (!actEmail.trim() || !actKey.trim()) { setActMsg("Enter email + key"); return; }
    setActBusy(true); setActMsg("");
    try {
      const status = await invoke<{ valid: boolean; plan: string; email: string | null; expires_at: number | null; message: string }>(
        "activate_license", { email: actEmail.trim(), key: actKey.trim() }
      );
      if (status.valid) {
        setLicenseValid(true); setLicenseEmail(status.email ?? actEmail);
        setShowActivation(false); setActKey(""); setActMsg("");
      } else {
        setActMsg(status.message || "Failed");
      }
    } catch (err) { setActMsg(String(err)); }
    finally { setActBusy(false); }
  };

  // ─── Render ────────────────────────────────────────

  return (
    <div className="w-screen h-screen flex flex-col bg-[#0a0a0f] text-white overflow-hidden">
      {/* Header — drag region except window buttons + Disconnect */}
      <div className="flex items-center h-10 bg-[#12121c] border-b border-white/5 flex-shrink-0 select-none">
        <div data-tauri-drag-region className="flex items-center gap-2 flex-1 min-w-0 px-4">
          <div className="w-5 h-5 rounded bg-gradient-to-br from-purple-500 to-rose-500 flex items-center justify-center text-[10px] font-bold">🔍</div>
          <span className="font-semibold text-sm">LeakScope</span>
          <span className="text-[10px] text-white/30">v{appVersion}</span>
          {isPro && (
            <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-gradient-to-r from-amber-400 to-orange-400 text-black">
              PRO{licenseValid && licenseEmail ? ` · ${licenseEmail.split("@")[0]}` : ""}
            </span>
          )}
          {token && (
            <span className="text-[10px] text-green-400">● GitHub Connected</span>
          )}
        </div>
        <div className="flex items-center h-full">
          {token && (
            <button onClick={disconnect} className="h-full px-4 text-[11px] text-white/40 hover:text-red-400 transition border-l border-white/5">Disconnect</button>
          )}
          <WinBtn onClick={handleMinimize} title="Minimize">
            {/* minus */}
            <svg width="10" height="10" viewBox="0 0 10 10"><rect x="1" y="4.5" width="8" height="1" fill="currentColor"/></svg>
          </WinBtn>
          <WinBtn onClick={handleToggleMax} title={isMaximized ? "Restore" : "Maximize"}>
            {isMaximized ? (
              /* restore icon (two overlapping squares) */
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                <rect x="2" y="3" width="6" height="5" stroke="currentColor" strokeWidth="1" fill="none"/>
                <rect x="3" y="2" width="5" height="5" stroke="currentColor" strokeWidth="1" fill="currentColor" fillOpacity="0.15"/>
              </svg>
            ) : (
              /* maximize icon */
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><rect x="1" y="1" width="8" height="8" stroke="currentColor" strokeWidth="1"/></svg>
            )}
          </WinBtn>
          <WinBtn onClick={handleClose} title="Close" variant="close">
            {/* close X */}
            <svg width="10" height="10" viewBox="0 0 10 10" stroke="currentColor" strokeWidth="1.2">
              <line x1="1.5" y1="1.5" x2="8.5" y2="8.5"/><line x1="8.5" y1="1.5" x2="1.5" y2="8.5"/>
            </svg>
          </WinBtn>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {step === "connect" && <ConnectScreen onConnect={startOAuth} onTokenPaste={handleTokenPaste} busy={oauthBusy} />}
        {step === "repos" && (
          <ReposScreen
            repos={filteredRepos}
            selected={selectedRepos}
            onToggle={toggleRepo}
            onToggleAll={toggleAll}
            filter={filter}
            onFilterChange={setFilter}
            onScan={startScan}
            isPro={isPro}
            licenseValid={licenseValid}
            scanMode={scanMode}
            onScanModeChange={setScanMode}
          />
        )}
        {step === "scanning" && (
          <ScanningScreen progress={scanProgress} findings={findings} onCancel={() => { scanCancelled.current = true; }} />
        )}
        {step === "results" && (
          <ResultsScreen
            findings={findings}
            setFindings={setFindings}
            onRescan={startScan}
            scanStats={scanStats}
            onBack={() => setStep("repos")}
            isPro={isPro}
            licenseValid={licenseValid}
          />
        )}
      </div>

      {/* Activation modal */}
      {showActivation && isPro && !licenseValid && (
        <div className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm flex items-center justify-center p-6">
          <div className="w-full max-w-md bg-[#12121c] rounded-2xl border border-white/10 p-8">
            <div className="text-center mb-6">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-400 to-orange-400 flex items-center justify-center text-2xl text-black mx-auto mb-3">🔑</div>
              <h2 className="text-xl font-semibold">Activate LeakScope Pro</h2>
              <p className="text-xs text-white/50 mt-1">Enter your license key from the purchase email</p>
            </div>
            <div className="space-y-3">
              <input value={actEmail} onChange={(e) => setActEmail(e.target.value)} placeholder="you@example.com"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder-white/30" />
              <input value={actKey} onChange={(e) => setActKey(e.target.value)} placeholder="LS-XXXX-XXXX-XXXX"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder-white/30 font-mono tracking-wider" />
              {actMsg && <div className="text-xs px-3 py-2 rounded bg-red-900/40 border border-red-500/30 text-red-300">{actMsg}</div>}
              <button onClick={handleActivate} disabled={actBusy}
                className="w-full py-3 rounded-lg font-semibold bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-black disabled:opacity-50">
                {actBusy ? "Activating..." : "✨ Activate"}
              </button>
              <p className="text-center text-[11px] text-white/40">
                <a href="https://magidiva.com/pro" target="_blank" className="hover:text-amber-400 underline">Don't have a key? Buy Pro →</a>
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Window Control Button ────────────────────────────

function WinBtn({ onClick, children, title, variant }: {
  onClick: () => void; children: React.ReactNode; title?: string; variant?: "close" | "default";
}) {
  const isClose = variant === "close";
  return (
    <button
      onClick={onClick}
      title={title}
      className={`
        h-full w-11 flex items-center justify-center text-white/50
        border-l border-white/5 transition-colors
        ${isClose
          ? "hover:bg-red-600 hover:text-white"
          : "hover:bg-white/10 hover:text-white"
        }
      `}>
      {children}
    </button>
  );
}

// ─── Connect Screen ────────────────────────────────────

function ConnectScreen({ onConnect, onTokenPaste, busy }: { onConnect: () => void; onTokenPaste: (t: string) => void; busy: boolean }) {
  const [manualToken, setManualToken] = useState("");
  const [showManual, setShowManual] = useState(false);

  return (
    <div className="h-full flex items-center justify-center p-8">
      <div className="max-w-md w-full text-center">
        <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-purple-500 via-pink-500 to-rose-500 flex items-center justify-center text-4xl mx-auto mb-6 shadow-xl shadow-purple-500/20">
          🔍
        </div>
        <h1 className="text-3xl font-bold mb-3">Scan your repos for leaked secrets</h1>
        <p className="text-white/60 mb-8">
          API keys, tokens, passwords, private certs. LeakScope finds them
          <span className="text-white"> before attackers do</span>.
          <br />100+ secret patterns, runs on your machine.
        </p>

        <button onClick={onConnect} disabled={busy}
          className="w-full py-4 rounded-xl font-semibold bg-white text-black hover:bg-white/90 transition flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed">
          {busy ? "Connecting..." : (
            <>
              <svg viewBox="0 0 16 16" width="20" height="20" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
              Connect with GitHub
            </>
          )}
        </button>

        {/* Manual token paste — for quick testing */}
        <button onClick={() => setShowManual(!showManual)}
          className="mt-4 text-xs text-white/40 hover:text-white/70 underline">
          {showManual ? "▼ Hide" : "▲"} Or paste a GitHub PAT directly
        </button>
        {showManual && (
          <div className="mt-3 bg-white/5 border border-white/10 rounded-xl p-4 text-left">
            <div className="text-[11px] text-white/50 mb-2">
              Create one at <a className="underline text-white/70" href="https://github.com/settings/tokens" target="_blank">github.com/settings/tokens</a> with <code className="bg-black/40 px-1 rounded">repo</code> scope.
            </div>
            <input
              value={manualToken}
              onChange={(e) => setManualToken(e.target.value)}
              placeholder="ghp_xxx... or github_pat_xxx..."
              className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 font-mono text-xs text-white placeholder-white/20 focus:border-purple-500/50 outline-none"
            />
            <button
              disabled={!manualToken.trim()}
              onClick={() => onTokenPaste(manualToken.trim())}
              className="mt-3 w-full py-2 rounded-lg text-sm font-semibold bg-gradient-to-r from-purple-600 to-pink-600 disabled:opacity-40 disabled:cursor-not-allowed hover:from-purple-500 hover:to-pink-500">
              Save token →
            </button>
          </div>
        )}

        <div className="mt-8 grid grid-cols-3 gap-3 text-left text-xs">
          {[
            ["100+", "secret patterns"],
            ["0$", "Cloudflare vs GHAS"],
            ["100%", "local & private"],
          ].map(([big, small]) => (
            <div key={big} className="bg-white/5 rounded-lg p-3">
              <div className="text-lg font-bold text-purple-400">{big}</div>
              <div className="text-white/50">{small}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Repos Screen ──────────────────────────────────────

function ReposScreen({ repos, selected, onToggle, onToggleAll, filter, onFilterChange, onScan, isPro, licenseValid, scanMode, onScanModeChange }: {
  repos: Repo[]; selected: Set<string>;
  onToggle: (fullName: string) => void;
  onToggleAll: () => void;
  filter: string; onFilterChange: (v: string) => void;
  onScan: () => void;
  isPro: boolean; licenseValid: boolean;
  scanMode: "head" | "history";
  onScanModeChange: (m: "head" | "history") => void;
}) {
  const maxSelect = (!isPro || !licenseValid) ? 5 : Infinity;
  const canScan = selected.size > 0 && selected.size <= maxSelect;
  const overLimit = selected.size > maxSelect;

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h2 className="text-lg font-semibold">Your GitHub Repositories</h2>
          <p className="text-xs text-white/40 mt-1">{repos.length} repos · {selected.size} selected</p>
        </div>
        <div className="flex gap-3">
          <input value={filter} onChange={(e) => onFilterChange(e.target.value)} placeholder="Filter repos..."
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm w-56" />
          <button onClick={onToggleAll} className="text-xs px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10">
            {selected.size === repos.length ? "Deselect All" : "Select All"}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-white/[0.02] rounded-xl border border-white/5">
        {repos.map((repo) => {
          const isSel = selected.has(repo.full_name);
          const isLocked = (!isPro || !licenseValid) && !isSel && selected.size >= maxSelect;
          return (
            <div key={repo.full_name}
              onClick={() => !isLocked && onToggle(repo.full_name)}
              className={`flex items-center gap-4 px-4 py-3 border-b border-white/5 cursor-pointer transition ${
                isSel ? "bg-purple-500/10" : "hover:bg-white/5"
              } ${isLocked ? "opacity-40 cursor-not-allowed" : ""}`}>
              <div className={`w-5 h-5 rounded border flex items-center justify-center ${
                isSel ? "bg-purple-500 border-purple-500" : "border-white/20"
              }`}>
                {isSel && <span className="text-white text-xs">✓</span>}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium truncate">{repo.full_name}</span>
                  {repo.is_private && <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400">Private</span>}
                  {repo.language && <span className="text-[10px] text-white/40">{repo.language}</span>}
                  <span className="text-[10px] text-white/30">★ {repo.stars}</span>
                </div>
                {repo.description && <div className="text-xs text-white/40 truncate mt-0.5">{repo.description}</div>}
              </div>
              {isLocked && <span className="text-[10px] text-amber-400">🔒 Community limit</span>}
            </div>
          );
        })}
        {repos.length === 0 && <div className="p-8 text-center text-white/40">No repos found</div>}
      </div>

      <div className="mt-4 flex items-center justify-between flex-shrink-0">
        <div className="text-xs text-white/40">
          {(!isPro || !licenseValid) && selected.size > 0 && (
            <span className={overLimit ? "text-red-400" : ""}>
              Community: max 5 repos · <a className="underline text-purple-400" href="https://magidiva.com/pro" target="_blank">Upgrade for unlimited →</a>
            </span>
          )}
          {isPro && licenseValid && <span className="text-green-400">✓ Pro — unlimited repos</span>}
        </div>

        {/* Scan mode toggle */}
        <div className="flex rounded-xl bg-white/5 border border-white/10 p-1">
          <button
            onClick={() => onScanModeChange("head")}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
              scanMode === "head" ? "bg-white/15 text-white" : "text-white/50 hover:text-white/80"
            }`}>
            HEAD only
          </button>
          <button
            onClick={() => onScanModeChange("history")}
            disabled={!isPro || !licenseValid}
            title={!isPro || !licenseValid ? "Git history scan requires Pro license" : "Scan full git history for secrets introduced in commits"}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center gap-1 ${
              scanMode === "history" ? "bg-amber-500/20 text-amber-300" : "text-white/50 hover:text-white/80"
            } ${(!isPro || !licenseValid) ? "opacity-40 cursor-not-allowed" : ""}`}>
            History {(!isPro || !licenseValid) && "🔒"}
          </button>
        </div>

        <button
          onClick={onScan}
          disabled={!canScan}
          className="px-6 py-3 rounded-xl font-semibold bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:opacity-40 disabled:cursor-not-allowed transition">
          🔍 Scan {selected.size} Repo{selected.size !== 1 ? "s" : ""}
        </button>
      </div>
    </div>
  );
}

// ─── Scanning Screen ───────────────────────────────────

function ScanningScreen({ progress, findings, onCancel }: {
  progress: { repo: string; file: string; done: number; total: number };
  findings: LeakFinding[];
  onCancel: () => void;
}) {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="max-w-lg w-full text-center">
        <div className="w-20 h-20 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-4xl mx-auto mb-6 animate-pulse">
          🔍
        </div>
        <h2 className="text-xl font-semibold mb-2">Scanning...</h2>
        <p className="text-xs text-white/50 font-mono truncate mb-1">
          {progress.repo || "Initializing..."}
        </p>
        <p className="text-[11px] text-white/30 font-mono truncate mb-6">
          {progress.file}
        </p>
        {progress.total > 0 && (
          <div className="w-full bg-white/10 rounded-full h-2 mb-2">
            <div className="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full transition-all"
              style={{ width: `${(progress.done / progress.total) * 100}%` }} />
          </div>
        )}
        <div className="text-xs text-white/40 mb-4">
          Files: {progress.done} / {progress.total} • Leaks found: <span className="text-red-400 font-bold">{findings.length}</span>
        </div>
        <button
          onClick={onCancel}
          className="px-6 py-2.5 rounded-xl text-sm font-semibold bg-white/5 border border-white/10 text-white/70 hover:bg-white/10 hover:text-red-400 hover:border-red-400/30 transition">
          ✕ Cancel scan
        </button>
      </div>
    </div>
  );
}

// ─── Results Screen ────────────────────────────────────

function ResultsScreen({ findings, setFindings, onRescan, onBack, isPro, licenseValid, scanStats }: {
  findings: LeakFinding[];
  setFindings: (fn: LeakFinding[] | ((prev: LeakFinding[]) => LeakFinding[])) => void;
  onRescan: () => void;
  onBack: () => void;
  isPro: boolean; licenseValid: boolean;
  scanStats: { repos: number; files: number; seconds: number; mode: string } | null;
}) {
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set()); // key: `${idx}` or group key
  const [grouped, setGrouped] = useState(true);
  const [revokeUrls, setRevokeUrls] = useState<Record<string, string | undefined>>({});

  const categories = ["all", ...Array.from(new Set(findings.map((f) => f.category)))];
  const filtered = categoryFilter === "all" ? findings : findings.filter((f) => f.category === categoryFilter);

  // Stats
  const stats = {
    total: findings.length,
    critical: findings.filter((f) => ["AI", "Payment", "Cloud"].includes(f.category)).length,
    files: new Set(findings.map((f) => `${f.path}:${f.line}`)).size,
    repos: new Set(findings.map((f) => f.path.split("/").slice(0, 2).join("/"))).size,
  };

  // Group by repo
  const repoGroups = grouped ? (() => {
    const map = new Map<string, LeakFinding[]>();
    for (const f of filtered) {
      const repoKey = f.path.split("/").slice(0, 2).join("/");
      if (!map.has(repoKey)) map.set(repoKey, []);
      map.get(repoKey)!.push(f);
    }
    return Array.from(map.entries()).sort((a, b) => b[1].length - a[1].length);
  })() : null;

  const toggleExpanded = (key: string) => {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key); else next.add(key);
    setExpanded(next);
  };

  // Pro: verify a single finding against origin API
  const verifyFinding = async (idx: number, f: LeakFinding) => {
    try {
      const ok = await invoke<boolean>("verify_token", { matched: f.matched, ruleId: f.rule_id });
      setFindings((prev) => prev.map((ff, i) => i === idx ? { ...ff, verified: ok } : ff));
    } catch {
      setFindings((prev) => prev.map((ff, i) => i === idx ? { ...ff, verified: false } : ff));
    }
  };

  // Export JSON report
  const exportJSON = () => {
    const report = {
      exported_at: new Date().toISOString(),
      total_findings: findings.length,
      stats: {
        critical: findings.filter((f) => ["AI", "Payment", "Cloud"].includes(f.category)).length,
        repos: new Set(findings.map((f) => f.path.split("/").slice(0, 2).join("/"))).size,
        files: new Set(findings.map((f) => `${f.path}:${f.line}`)).size,
      },
      findings: findings.map((f) => ({
        rule_id: f.rule_id,
        rule_name: f.rule_name,
        category: f.category,
        path: f.path,
        line: f.line,
        entropy: f.entropy,
        matched: f.display_matched, // masked in export too
        verified: f.verified,
      })),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `leakscope-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Load revoke URL on demand
  const loadRevokeUrl = async (ruleId: string) => {
    if (revokeUrls[ruleId] !== undefined) return;
    try {
      const url = await invoke<string | null>("get_revoke_url", { ruleId });
      setRevokeUrls((prev) => ({ ...prev, [ruleId]: url ?? "" }));
    } catch {
      setRevokeUrls((prev) => ({ ...prev, [ruleId]: "" }));
    }
  };

  const catColor: Record<string, string> = {
    "AI": "bg-violet-500/20 text-violet-300 border-violet-500/30",
    "Payment": "bg-red-500/20 text-red-300 border-red-500/30",
    "Cloud": "bg-amber-500/20 text-amber-300 border-amber-500/30",
    "Communication": "bg-sky-500/20 text-sky-300 border-sky-500/30",
    "Dev": "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    "Database": "bg-rose-500/20 text-rose-300 border-rose-500/30",
    "Infra": "bg-indigo-500/20 text-indigo-300 border-indigo-500/30",
    "Monitoring": "bg-teal-500/20 text-teal-300 border-teal-500/30",
    "Misc": "bg-white/10 text-white/50 border-white/20",
  };

  const renderFinding = (f: LeakFinding, idx: number) => {
    const key = `${idx}-${f.rule_id}-${f.line}`;
    const isExpanded = expanded.has(key);
    const needsPro = !isPro || !licenseValid;
    const shortPath = f.path.split("/").slice(2).join("/"); // strip owner/repo prefix

    return (
      <div key={key} className="bg-white/[0.02] border border-white/5 rounded-xl overflow-hidden">
        <div onClick={() => toggleExpanded(key)} className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-white/5">
          <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded border ${catColor[f.category] || catColor["Misc"]}`}>{f.category}</span>
          <span className="font-medium text-sm truncate flex-1">{f.rule_name}</span>
          <span className="text-[10px] text-white/40 font-mono truncate max-w-[280px]">{shortPath}</span>
          <span className="text-[10px] text-white/30">L{f.line}</span>
          <span className={`text-xs transition ${isExpanded ? "rotate-180" : ""}`}>▼</span>
        </div>
        {isExpanded && (
          <div className="px-4 pb-4 border-t border-white/5 space-y-3">
            {/* Matched secret — masked for safety */}
            <div>
              <div className="text-[10px] text-white/40 mb-1 flex items-center gap-2">
                <span>Detected pattern ({f.entropy.toFixed(1)} bits entropy)</span>
                {!needsPro && f.verified === undefined && (
                  <button
                    onClick={(e) => { e.stopPropagation(); verifyFinding(idx, f); }}
                    className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/30">
                    🔎 Verify live
                  </button>
                )}
                {f.verified === true && <span className="text-[10px] text-red-400 font-semibold">⚠ LIVE on origin API</span>}
                {f.verified === false && <span className="text-[10px] text-green-400 font-semibold">✓ Revoked / inactive</span>}
              </div>
              <div className="bg-black/40 border border-red-500/30 rounded-lg px-3 py-2 font-mono text-xs text-red-300 break-all">
                {f.display_matched}
              </div>
            </div>
            {/* Context snippet — highlight matched portion */}
            <div>
              <div className="text-[10px] text-white/40 mb-1">File context (L{f.line}):</div>
              <HighlightedSnippet snippet={f.snippet} rawMatched={f.matched} displayMatched={f.display_matched} />
            </div>
            {/* Action bar */}
            <div className="flex items-center justify-between bg-white/5 border border-white/10 rounded-lg px-3 py-2">
              <div className="flex items-center gap-3">
                {(() => {
                  const [owner, repo, ...rest] = f.path.split("/");
                  const repoUrl = `https://github.com/${owner}/${repo}/blob/${rest.length > 0 ? f.path.split("/").slice(2).join("/") : ""}#L${f.line}`;
                  return (
                    <a href={repoUrl} target="_blank" rel="noopener noreferrer"
                      onClick={(e) => { e.stopPropagation(); }}
                      className="text-xs text-white/60 hover:text-white flex items-center gap-1">
                      📂 Open in GitHub
                    </a>
                  );
                })()}
                <span className="text-[10px] text-white/30 font-mono">{f.rule_id}</span>
              </div>
              {needsPro ? (
                <a href="https://magidiva.com/pro" target="_blank" onClick={(e) => e.stopPropagation()}
                  className="text-xs font-semibold underline text-amber-400 hover:text-amber-300">
                  🔒 Pro: verify + revoke
                </a>
              ) : (
                <RevokeLink ruleId={f.rule_id} revokeUrls={revokeUrls} loadRevokeUrl={loadRevokeUrl} />
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="p-6 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div className="flex items-center gap-6">
          <h2 className="text-lg font-semibold">Scan Results</h2>
          <div className="flex gap-3 text-sm">
            <div className="bg-red-500/20 border border-red-500/30 text-red-300 px-3 py-1 rounded-lg">
              {stats.total} leaks found
            </div>
            <div className="bg-amber-500/20 border border-amber-500/30 text-amber-300 px-3 py-1 rounded-lg">
              {stats.critical} high-risk
            </div>
            <div className="bg-white/5 text-white/60 px-3 py-1 rounded-lg">
              {stats.repos} repos · {stats.files} files
            </div>
          </div>
          {scanStats && (
            <div className="text-[11px] text-white/40 font-mono pl-4 border-l border-white/10">
              scanned <span className="text-white/60">{scanStats.repos}</span> repo{scanStats.repos > 1 ? "s" : ""}
              {scanStats.files > 0 && <> · <span className="text-white/60">{scanStats.files}</span> files</>}
              {" · "}<span className="text-white/60">{scanStats.seconds}s</span>
              {" · "}{scanStats.mode}
            </div>
          )}
        </div>
        <div className="flex gap-2">
          <button onClick={exportJSON} title="Export JSON report" className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-xs">
            📥 Export JSON
          </button>
          <button onClick={() => setGrouped(!grouped)} className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-xs">
            {grouped ? "📊 Flat" : "📁 By Repo"}
          </button>
          <button onClick={onBack} className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-sm">← Back</button>
          <button onClick={onRescan} className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-sm font-semibold">
            🔄 Rescan
          </button>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="text-6xl mb-4">🛡️</div>
            <h3 className="text-xl font-semibold mb-2">Your repos are clean!</h3>
            <p className="text-white/50">No leaked secrets found in scanned repos.</p>
          </div>
        </div>
      ) : (
        <>
          {/* Category filter */}
          <div className="flex gap-2 mb-4 flex-shrink-0 overflow-x-auto">
            {categories.map((c) => (
              <button key={c} onClick={() => setCategoryFilter(c)}
                className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap transition ${
                  categoryFilter === c ? "bg-purple-600 text-white" : "bg-white/5 text-white/60 hover:bg-white/10"
                }`}>
                {c === "all" ? "All" : c}
                {c !== "all" && ` (${findings.filter((f) => f.category === c).length})`}
              </button>
            ))}
          </div>

          {/* Findings */}
          <div className="flex-1 overflow-auto space-y-3">
            {grouped && repoGroups ? repoGroups.map(([repoKey, repoFindings]) => {
              const groupExpanded = !expanded.has(`repo-${repoKey}`) || expanded.has(`repo-${repoKey}`);
              const criticalCount = repoFindings.filter((f) => ["AI", "Payment", "Cloud"].includes(f.category)).length;
              return (
                <div key={repoKey} className="bg-white/[0.03] border border-white/10 rounded-2xl overflow-hidden">
                  <div onClick={() => toggleExpanded(`repo-${repoKey}`)} className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-white/5 border-b border-white/5">
                    <span className="text-base">📁</span>
                    <span className="font-semibold text-sm">{repoKey}</span>
                    <span className="text-[10px] text-white/40 bg-white/10 px-2 py-0.5 rounded-full">{repoFindings.length} leak{repoFindings.length !== 1 ? "s" : ""}</span>
                    {criticalCount > 0 && (
                      <span className="text-[10px] text-red-300 bg-red-500/20 border border-red-500/30 px-2 py-0.5 rounded-full">⚠ {criticalCount} critical</span>
                    )}
                    <span className={`ml-auto text-xs text-white/40 transition ${groupExpanded ? "rotate-180" : ""}`}>▼</span>
                  </div>
                  {groupExpanded && (
                    <div className="p-3 space-y-2">
                      {repoFindings.map((f, idx) => renderFinding(f, idx))}
                    </div>
                  )}
                </div>
              );
            }) : filtered.map((f, idx) => renderFinding(f, idx))}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Revoke Link — lazy-loads URL from backend ─────────

function RevokeLink({ ruleId, revokeUrls, loadRevokeUrl }: {
  ruleId: string;
  revokeUrls: Record<string, string | undefined>;
  loadRevokeUrl: (id: string) => void;
}) {
  const state = revokeUrls[ruleId];

  if (state === undefined) {
    loadRevokeUrl(ruleId);
    return <span className="text-[10px] text-white/30">Loading revoke link...</span>;
  }
  if (!state) {
    return <span className="text-[10px] text-white/30">No revoke URL in our database</span>;
  }
  return (
    <a href={state} target="_blank" rel="noopener noreferrer"
      onClick={(e) => { e.stopPropagation(); }}
      className="text-xs font-semibold text-rose-400 hover:text-rose-300 underline flex items-center gap-1">
      🔐 Revoke at source →
    </a>
  );
}

// ─── Snippet with matched part highlighted ─────────────

function HighlightedSnippet({ snippet, rawMatched, displayMatched }: {
  snippet: string; rawMatched: string; displayMatched: string;
}) {
  // Replace raw matched with masked version in the snippet
  const safeSnippet = snippet.includes(rawMatched)
    ? snippet.split(rawMatched).join(displayMatched)
    : snippet;

  const idx = safeSnippet.indexOf(displayMatched);
  if (idx >= 0) {
    const before = safeSnippet.slice(0, idx);
    const after = safeSnippet.slice(idx + displayMatched.length);
    return (
      <pre className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 font-mono text-xs text-white/70 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
        {before}
        <span className="bg-red-500/40 text-red-200 px-1 rounded border border-red-500/50">{displayMatched}</span>
        {after}
      </pre>
    );
  }
  return (
    <pre className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 font-mono text-xs text-white/70 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
      {safeSnippet}
    </pre>
  );
}
