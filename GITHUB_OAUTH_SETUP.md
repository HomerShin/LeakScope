# LeakScope — GitHub OAuth App 创建

> 5 分钟手动操作。需要 GitHub 账号登录。

---

## Step 1: 创建 OAuth App

1. 打开 https://github.com/settings/developers
2. 点 **New OAuth App**
3. 填写：

| 字段 | 值 |
|------|-----|
| **Application name** | `LeakScope` |
| **Homepage URL** | `https://leakscope.com` |
| **Authorization callback URL** | `http://localhost` |
| **Application description** | `Scan your repos for leaked secrets` |

4. 点 **Register application**

---

## Step 2: 拿到 Client ID + Client Secret

注册完后会显示：

```
Client ID: Iv1.xxxxxxxxxxxxxxxx
Client Secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**复制 Client ID**（不需要 secret，因为 LeakScope 用 device flow）

---

## Step 3: 改 LeakScope 代码

打开 `F:\LeakScope\src-tauri\src\github.rs`，找：

```rust
const GITHUB_CLIENT_ID: &str = "Iv1.LeakScopeDeviceFlow";
```

改成你刚才复制的：

```rust
const GITHUB_CLIENT_ID: &str = "Iv1.你复制的那个ClientID";
```

Client Secret **不要** 放代码里 — device flow 不需要它（安全！）

---

## Step 4: 重构建

```powershell
cd F:\LeakScope
pnpm release
```

或者只跑 Rust check 确认：
```powershell
cd F:\LeakScope\src-tauri
cargo check
```

---

## Step 5: 测试 OAuth Device Flow

1. 启动 LeakScope
2. 点 **Connect with GitHub**
3. 会弹浏览器打开 `github.com/login/device`
4. 输入显示的 **user code**（LeakScope 窗口里会显示）
5. 点 **Authorize**
6. 回到 LeakScope — 应该自动加载你的 repos

---

## ⚠️ 重要：授权 Scopes

LeakScope 请求的 scope 是：
```
repo read:org read:user
```

- `repo` — 访问 public + private repos
- `read:org` — 列出组织的 repos
- `read:user` — 基本用户信息

**OAuth App 创建后，GitHub 可能要求你申请 "Repo" scope 扩展权限**。如果报 403：
1. 回 https://github.com/settings/developers → LeakScope app
2. 检查 Scopes 设置
3. 如果需要，去 GitHub Support 申请扩展

---

## Step 6: 测试 Scan

OAuth 成功后：
1. 选择 3 个 repos（Community 限 5 个）
2. 点 **🔍 Scan**
3. 等进度条跑完
4. 看 Results — 应该能扫出 leaked token / key / password

**测试用 repo**: 找一个你自己有 demo secrets 的 repo（或者故意往某个 test repo 里放一个 `sk-fake-test-12345678901234567890`）

---

## 完成后

LeakScope 的 MVP 就真的能跑了。然后：
1. 推 GitHub repo（`HomerShin/LeakScope`）
2. Creem 新建 $29 product
3. 复用 MagiDiva 的 Worker（加 `plan=leakscope` 参数）
4. Landing Page → Product Hunt
