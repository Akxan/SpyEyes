# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5 / Tor / I2P，借鉴 Maigret)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- 首次 upload 到 PyPI（package 重构已完成，`pip install .` 已 work，剩 `twine upload`）
- Docker 镜像
- curl_cffi 浏览器指纹伪装可选（`spyeyes[stealth]`，绕过 Cloudflare）

---

## [1.6.11] — 2026-05-09

⚡ **域名邮箱深度爬取修复"看着卡死"+ 实际提速 2×**(用户反馈)

### 背景

用户截图显示 domain-emails 跑到 "阶段 3/4:深度爬取 2 个目标" 后**完全静默**,1+ 分钟感觉卡死。

实际不是卡死,是两个原因叠加:

1. **`max_pages=500` 太大** — 2 target × 250 页 × 500ms 速率 = **理论最低 4 分钟**
2. **v1.6.6 多 target 并行时,内部 `show_progress=False`** — 期间没有任何反馈

### 修复 1:降低默认 max_pages

```
DOMAIN_EMAIL_DEFAULT_MAX_PAGES:  500 → 200
DOMAIN_EMAIL_PER_TARGET_CAP:    新增 100(单 target 最多 100 页)
```

实践:典型企业域 contact / about / team 等高邮箱密度页 < 100 页。
长尾页面邮箱密度急剧降到几乎 0,纯花时间不出货。

效果:
- 1 target:200 页(原 500)→ 速率限制部分 100s → 50s
- 2 target:各 100 页 → ~50s × 2 并行 ≈ 50s(整体 4 分钟 → 1 分钟)

### 修复 2:并行 target 也保留进度反馈

之前 v1.6.6 为防输出交织把内部 `show_progress=False`。改成:
- 用 `\n` 替代 `\r`(并行时 `\r` 互相覆盖)
- 加 `[target]` 前缀让用户知道是哪个 target 的进度
- 加 `_DEMAIL_PROGRESS_LOCK` 互斥写 stderr,行不会切碎
- 频率从每 10 → 20 页(降噪声)

效果:
```
之前(silent 1+ 分钟):
  阶段 3/4:深度爬取 2 个目标 ...
  (1+ 分钟无任何输出 ← 用户以为卡死)

现在:
  阶段 3/4:深度爬取 2 个目标 ...
     [api.example.com] pages=20/100 emails=3 queue=45
     [www.example.com] pages=20/100 emails=2 queue=23
     [api.example.com] pages=40/100 emails=5 queue=67
     [www.example.com] pages=40/100 emails=4 queue=12
     ...
```

### 用户可覆盖

如果你需要更深度的爬取(论文研究 / 大型站):

```bash
spyeyes domain-emails example.com --max-pages 500
```

### Tests / Lint

无变化(只调常量)。**488 全绿**。ruff 0 / mypy 0 / bandit 0。

### Packaging

- `__version__` 1.6.10 → 1.6.11

---

## [1.6.10] — 2026-05-09

🐛 **PDF 西文带变音符字符渲染修复**(用户反馈截图)

### 背景

PDF 报告里西班牙语 / 法语 / 德语等带变音符的拉丁字符渲染异常:

```
正确:  Comparador de Envíos | Logística Inteligente
之前:  Comparador de Enví os | Logí stic Inteligente
                  ↑ 多余空格        ↑ 字符被切
```

### 根因

`_PDF_LATIN_RUN_RE` 之前是 `[\x20-\x7E]+`,只匹配 ASCII。`í ñ é ü ç` 等 Latin-1 Supplement 字符(U+00A0-U+00FF)fall through 到 STSong-Light 中文字体 — 该字体不含这些字形,reportlab 字体回退失败 → 插入诡异空格。

### 修复

regex 扩展到完整 Western 字符集:

```python
# v1.6.10:扩展到 Latin-1 Supplement + 常用标点
r'[\x20-\x7E\xa0-\xff‐-―‘-”…]+'
```

覆盖范围:
- ASCII 可打印(`\x20-\x7E`)
- **Latin-1 Supplement**(`\xa0-\xff`)— 西/法/德/葡/意/英 全部带变音符:**í ñ é ü ç á à â î ô ê û è ò ó ú ý ÿ Ä Ö Ü ß** 等
- Em / en dash(`‐-―`)
- Smart quotes(`‘-”`)
- Ellipsis(`…`)

Helvetica 的 WinAnsi 编码完整支持上述区域。

### 实测

```
原文: Comparador de Envíos | Logística Inteligente
处理后: <font name="Helvetica">Comparador de Envíos | Logística Inteligente</font>
       ↑ 整体被一个 Helvetica 标签包住,不再切分
```

### 影响范围

修复任何含西文带变音符的 PDF 内容:
- 国际化网站 title(西班牙语 / 法语 / 德语 / 葡萄牙语)
- WHOIS 注册组织名(欧洲公司常含 ä ö ü)
- 邮箱报告里的西文姓名(José / Müller / François)

### 注意

- Latin Extended-A(波兰语 ł / 捷克语 ž / 匈牙利语 ő)仍可能 fall through — 这部分 Helvetica WinAnsi 不全;OSINT 西方主流用例不受影响
- 中日韩 / 阿拉伯语等仍走 STSong-Light(原本就 OK)

### Tests / Lint

无变化(只改正则)。**488 全绿**。ruff 0 / mypy 0 / bandit 0。

### Packaging

- `__version__` 1.6.9 → 1.6.10

---

## [1.6.9] — 2026-05-09

🐛 **修复 PDF 报告里 6 源状态行 emoji 乱码**(用户反馈截图)

### 背景

v1.6.8 引入"完整 6 源状态"用了 emoji `✅⊘❌`,在终端 / HTML 显示正常,但 PDF 用 `STSong-Light` 中文字体不支持 emoji 字符,reportlab 字体回退失败,渲染成随机汉字:

```
之前 PDF:  丅 certspotter: 21  丅 crtsh: 20  謁 hackertarget: 0  ...
                                              ↑ 乱码
```

### 修复

emoji 换成所有 CJK 字体都支持的 Unicode 文本符号:

| 之前 | 现在 | 含义 |
|---|---|---|
| ✅ | **✓** (U+2713 CHECK MARK) | 源成功 |
| ⊘ | **○** (U+25CB WHITE CIRCLE) | 源返空 |
| ❌ | **✗** (U+2717 BALLOT X) | 源出错 |

```
现在 PDF:  ✓ certspotter: 21  ✓ crtsh: 20  ○ hackertarget: 0  ...
                                              ↑ 正常显示
```

跨终端 / HTML / PDF / Markdown / TXT 全部一致渲染。

### 注意

PDF 里其它已有的 ✓✗⚠ 字符(SMTP 验证 / wildcard 警告等)早就在用,这版只补了 v1.6.8 新加的 source breakdown。

### Tests / Lint

无变化(只改字符,逻辑不动)。**488 全绿**。ruff 0 / mypy 0 / bandit 0。

### Packaging

- `__version__` 1.6.8 → 1.6.9

---

## [1.6.8] — 2026-05-09

✨ **`~/.spyeyes/env` 自动加载 + 报告显示完整 6 源状态**(用户连续反馈)

### 改动 1:`~/.spyeyes/env` 文件自动加载 API keys

之前用 macOS LaunchAgent (`com.akxan.spyeyes.envvars.plist`) 持久化 env vars,但:
- 在 macOS Sequoia 系统设置→登录项里显示"sh - 项目来自身份不明的开发者"(警告 + 污染)
- 跨平台不一致(Windows/Linux 没 LaunchAgent)
- 改 key 要重启

改用 SpyEyes 项目内自管的 `~/.spyeyes/env`(KEY=VALUE 格式),模块加载时自动读:

```bash
# ~/.spyeyes/env(权限 600,仅本用户)
SPYEYES_OTX_API_KEY=...
SPYEYES_CERTSPOTTER_API_KEY=...
PDCP_API_KEY=...
```

特性:
- 跨平台(macOS/Linux/Windows 一致)
- shell `export` 优先(已有 env vars 不被覆盖)
- 支持 `# 注释` + 空行 + 单/双引号
- 修改后下次跑立即生效,无需重启

### 改动 2:报告显示完整 6 源状态(✅/⊘/❌)

用户多次反馈"为什么数据源数字一会 2 一会 3,看不到内部"。

之前所有报告(HTML/PDF/Markdown/TXT)只显示总数:
```
共发现 273 个 · 活跃 33 个 · 来自 2 个数据源     ← 哪 2 个?
```

现在多打一行**完整 6 源状态**:
```
共发现 273 个 · 活跃 33 个 · 来自 2 个数据源
数据源:✅ certspotter: 36  ⊘ crtsh: 0  ❌ hackertarget (错误)  ✅ otx: 23  ⊘ wayback: 0  ✅ subfinder: 45
```

| 符号 | 含义 |
|---|---|
| ✅ N | 源成功返 N 个 hosts |
| ⊘ 0 | 源跑 OK 但返空(API 限速 / 域无数据 / 无 key) |
| ❌ (错误) | 源抛异常(连接失败 / 超时) |

### 9 轮循环测试结果(用户要求)

跨 3 个域 × 3 轮验证源稳定性:

| 源 | 跨 9 次活跃率 | 类型 |
|---|---|---|
| certspotter | 9/9 (100%) | 🟢 骨干 |
| subfinder | 9/9 (100%) | 🟢 骨干 |
| otx | 8/9 (89%) | 🟢 骨干 |
| crtsh | 3/9 (33%) | 🟡 机会 |
| wayback | 2/9 (22%) | 🟡 机会 |
| hackertarget | 0/9 (0%) | 🔴 quota 耗尽,需等 |

**结论:3 个骨干源数据完全稳定,3 个机会源是赠品。看到 "X 个数据源" 在 3-6 间浮动 = 骨干 3 + 机会 0~3 是正常的。**

### 应用范围

报告生成器都加了完整 6 源状态:
- 终端 `print_subdomains`(已有,format 升级)
- Markdown 报告
- HTML 报告(带样式)
- PDF 报告(斜体)
- TXT 报告

### Tests

- 7 个新测试 `TestLoadEnvFile`(共 **488 全绿**):
  - `test_loads_simple_key_value` — 基本格式
  - `test_handles_comments_and_blank_lines` — 注释 / 空行跳过
  - `test_strips_quotes` — 单引号 / 双引号
  - `test_existing_env_wins` — shell 优先
  - `test_missing_file_returns_zero` — 文件不存在静默
  - `test_malformed_lines_skipped` — 无 `=` / 空 key 跳过
  - `test_value_with_equals_sign` — value 含 `=`(用 partition)

### Code Quality

ruff 0 / mypy 0 / bandit 0

### Packaging

- `__version__` 1.6.7 → 1.6.8

### 升级 / 迁移指南

如果你之前用了 v1.6.5/6 的 LaunchAgent 方案:

```bash
# 1. 卸载 LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.akxan.spyeyes.envvars.plist
rm ~/Library/LaunchAgents/com.akxan.spyeyes.envvars.plist

# 2. 创建 ~/.spyeyes/env(把 key 写进去,KEY=VALUE 格式)
mkdir -p ~/.spyeyes
nano ~/.spyeyes/env
chmod 600 ~/.spyeyes/env
```

升级后系统设置→登录项里那个"sh"会消失。

---

## [1.6.7] — 2026-05-09

✨ **HTTP probe 抓全部状态码 title + CNAME 完整 chain**(用户反馈 2 件)

### 改动 1:`<title>` 不再跳过 4xx/5xx

之前 `if 200 <= status < 400` 才提取,理由是"404 Not Found 是噪声"。
但用户反馈截图(linux.do 全是 CF 403):**title 列空一片**,而真实情况是:

| 状态码 | 之前 | 现在 | 信息价值 |
|---|---|---|---|
| 403 (Cloudflare 挑战) | 空 | `Just a moment...` | 知道被 WAF 挡了 |
| 403 (其它 WAF) | 空 | `Attention Required!` | 同上 |
| 404 | 空 | `Page Not Found` / 真站点 404 | 区分 nginx 默认 vs 真 404 |
| 401 | 空 | `Sign in` / `Login` | 看到登录页存在 |
| 500 | 空 | 错误信息 | 服务器实际情况 |

实测:`ads.linux.do` 状态 403,title 现在显示 `Just a moment...`(Cloudflare 挑战页)。

注:JS / HTML body host 提取(v1.4.9)仍只对 2xx/3xx 做 — CF 错误页不会含真实业务 host 引用,避免噪声进 extracted_hosts。

### 改动 2:CNAME 完整 chain(最多 5 跳)

之前只抓**第一级** CNAME。多级链路被吃:
```
www.x.com  CNAME  cdn1.x.com
cdn1.x.com CNAME  cdn-real.cloudflare.net
                  ↑ 看不到
```

现在递归跟到底,用 ` → ` 连接:
```
cname: cdn1.x.com → cdn-real.cloudflare.net
```

实测:
```
autodiscover.akxan.com  → adsredir.ionos.info  (单级,跟之前一样)
www.github.com          → github.com           (单级)
某些站                  → cdn1.x → cdn2.x → cdn-real.cf.net  (新支持)
```

防循环:最多 5 跳,seen set 自我检测。

### Tests

- `test_probe_extracts_title_for_4xx_v167` — 403 抓 title
- `test_probe_extracts_title_for_404` — 404 抓 title
- `test_probe_no_title_extracted_when_body_empty` — body 空时正确返 None

替换之前 `test_probe_skips_title_for_4xx`(behavior 反了)。

**481 全绿**(+2 新,−1 旧调整)。ruff 0 / mypy 0 / bandit 0。

### Packaging

- `__version__` 1.6.6 → 1.6.7

---

## [1.6.6] — 2026-05-09

⚡ **域名邮箱挖掘提速 3-4× — HTTP probe 过滤 + 多 target 并行**(用户反馈)

### 背景

用户截图显示 `linux.do` 跑 domain-emails 时,33 个 alive 子域大部分是 `pages=0 emails=0`(像 `pop.linux.do` / `smtp.linux.do` / `dns.linux.do`)。这些**根本没 HTTP 服务**,但代码挨个发请求等超时,5+ 分钟。

### 优化(三件)

#### 1. `enumerate_subdomains` 调用改 `probe=True`

之前 `probe=False` 拿不到 HTTP 状态,33 个 DNS-alive 子域全爬。
现在 `probe=True` + 过滤 `http_status is not None`:
- linux.do: 33 个 alive → ~10 个 web-responsive
- 4xx/5xx 也算(服务器在,只是要认证)
- 纯 mail/DNS/SSH 主机自动跳过

#### 2. 多 target 并行爬虫(`TARGET_PARALLEL_WORKERS = 3`)

之前串行 `for target in targets`,每个等完才下一个。
现在 ThreadPoolExecutor(workers=3):
- 单 target 内部仍 500ms 速率限制(单域礼貌)
- 多 target 之间并发 → 3× 吞吐
- Ctrl+C 可中断

#### 3. 进度反馈 — 内部 `show_progress=False`

并行场景下多个 target 的进度条会输出交织变乱。所以单 target 内部静默,主流程在每个 target 完成后打一行总结:

```
[3/10] api.linux.do  pages=87 emails=12
[5/10] cdn.linux.do  pages=23 emails=0
[7/10] www.linux.do  pages=156 emails=8
...
```

颜色编码:有邮箱 = 绿,空 = 蓝(信息性,不算错误)。

### 实测

| 场景 | v1.6.5 | v1.6.6 | 提速 |
|---|---|---|---|
| `linux.do` 33 alive(其中 ~10 真 web) | ~5.5 分钟 | ~1.5 分钟 | **~3.5×** |
| 小域(< 5 alive) | ~30s | ~20s | ~1.5× |
| 单域(`--no-include-subdomains`) | 不变 | 不变 | — |

### Tests

无新测试(行为是性能优化,既有测试覆盖核心逻辑)。**479 全绿**。

### Code Quality

ruff 0 / mypy 0 / bandit 0

### Packaging

- `__version__` 1.6.5 → 1.6.6

---

## [1.6.5] — 2026-05-09

🐛 **`--alive-only` 智能升级 — 在 wildcard DNS / 劫持环境下自动严格过滤**

### 背景

用户截图显示 `akxan.com` 报告中 259 个"alive"子域,但实际只有 1 个真实站点。原因:用户机器开了 WARP / VPN / 公司代理拦截 DNS,所有 `*.akxan.com` 查询都被劫持到 `198.18.1.x`(TEST-NET-2),导致每个查询都"DNS 解析成功"→ alive=True。

之前 `--alive-only` 的过滤标准只看 `alive`(DNS 解析),无法识别这种 fake "活"。

### 修复

抽出 `_filter_alive_only(data)` 助手函数,**自动根据 wildcard 检测结果切换过滤标准**:

| 场景 | 过滤标准 | mode 字段 |
|---|---|---|
| `wildcard_suspect=False`(正常) | `alive=True` | `alive_only` |
| `wildcard_suspect=True`(劫持/wildcard) | `alive=True AND (HTTP 响应 OR 真实 CNAME)` | `alive_only_strict` |

**为什么严格模式用 HTTP 响应或 CNAME:**
- 劫持的 fake IP 不会有真实 web 服务响应 → HTTP probe 必然失败
- 真实 CNAME 是 wildcard 不会伪造的强证据(链路真实)
- HTTP 4xx/5xx 也算真实站点(401/403 = 服务器在,只是要认证)

### 实测对比(用户的 akxan.com 截图场景)

| | v1.6.4 | v1.6.5 |
|---|---|---|
| 报告显示子域数 | 259(全是 fake) | ~1-2(只剩真实 akxan.com) |
| 用户体验 | "为什么没过滤?" | 报告整洁,wildcard 警告依旧显示 |

### 三处统一接入

CLI handler / 交互菜单 / `_run_subdomain_batch` 都从内联过滤代码切到调用 `_filter_alive_only(data)`,DRY + 行为一致。

### `_filtered` 元数据扩展

```json
{
  "_filtered": {
    "mode": "alive_only_strict",   // 之前只有 'alive_only'
    "hidden": 257,
    "wildcard_suspect": true        // 新字段,报告生成器可显示警告
  }
}
```

### Tests

- 6 个新测试 `TestFilterAliveOnly`(共 **479 全绿**):
  - `test_no_wildcard_keeps_all_alive` — 正常场景行为不变
  - `test_wildcard_uses_strict_mode` — 严格模式过滤 fake hosts
  - `test_wildcard_keeps_4xx_5xx_responses` — 401/403 算真实
  - `test_alive_false_always_filtered` — 双场景一致
  - `test_invalid_input_returns_unchanged` — 容错
  - `test_filtered_metadata_count_correct` — 计数准确

### Code Quality

ruff 0 / mypy 0 / bandit 0

### Packaging

- `__version__` 1.6.4 → 1.6.5

---

## [1.6.4] — 2026-05-09

🐛 **报告默认目录改回英文 `Downloads/`**(用户反馈)

### 背景

v1.6.3 用了中文 `下载/`,用户反馈太"中文化",在某些环境不友好:

- SSH / scp / rsync 传输路径含非 ASCII 字符可能需要额外转义
- Windows CMD / 老 PowerShell 处理 Unicode 路径有时显示乱码
- 部分 CI/CD pipeline 对非 ASCII 文件名敏感
- 国际协作 / Issue 截图里 `下载/` 让英文用户困惑

### 修复

`下载/` → `Downloads/`(单数大写,沿袭 macOS / Windows 标准命名)

```bash
cd ~/work
spyeyes subdomain example.com --save report.html
# v1.6.3:→ ~/work/下载/report.html  ← 中文
# v1.6.4:→ ~/work/Downloads/report.html  ← 英文(现在)
```

### 已经存的旧报告怎么办

留在 `下载/` 文件夹里的旧报告**不会被自动迁移**。如果需要,手动 `mv ./下载/* ./Downloads/` 即可。

### Tests

5 个测试更新断言从 `'下载'` 改成 `'Downloads'`,共 **473 全绿**。

### Packaging

- `__version__` 1.6.3 → 1.6.4

---

## [1.6.3] — 2026-05-09

✨ **报告默认保存目录跨平台统一 — `<cwd>/下载/`**(用户反馈)

### 背景

用户反馈:"如果项目装在 Linux 服务器,默认存到 ~/Downloads,但服务器上没这个文件夹"。

之前(v1.2.0+)的优先级:`~/Downloads → ~/Download → ~/spyeyes-reports → cwd`,导致:
- macOS / Windows 桌面用户:存到 `~/Downloads/` ✓
- Linux 服务器用户:fallback 到 `~/spyeyes-reports/` — 不直观,用户不知道在哪
- 不同平台体验不一致

### 修复 — 统一行为

**所有平台默认都用 `<cwd>/下载/`**:你在哪跑命令,就在哪建文件夹,所见即所得。

```
新优先级:
1. SPYEYES_REPORTS_DIR (用户显式配置,如 /var/log/spyeyes)
2. <cwd>/下载/ (默认,自动创建)
3. <cwd> (兜底,极少见)
```

### 用户场景

```bash
# 普通使用 — 报告就在你跑命令的目录下的 下载/ 子文件夹
cd ~/work
spyeyes subdomain example.com --save report.html
# → ~/work/下载/report.html

# 服务器场景 — 用 env var 指定固定位置
export SPYEYES_REPORTS_DIR=/var/log/spyeyes
spyeyes ...
# → /var/log/spyeyes/...

# 也支持 systemd unit 里 Environment= 指定
```

### 移除的行为

- 不再读 `~/Downloads` / `~/Download`(保持跨平台一致,而不是 OS 依赖)
- 不再缓存 `_DEFAULT_REPORT_DIR_CACHE` — 用户在交互菜单里 `cd` 后再保存能正确响应新 cwd
- 已存在的 `~/Downloads/` 上**不影响已保存的旧报告**,只影响新保存的默认路径

### Tests

- 5 个新测试(共 **473 全绿**):
  - `test_default_creates_xiazai_in_cwd` — 默认行为
  - `test_env_var_override` — `SPYEYES_REPORTS_DIR` 覆盖
  - `test_env_var_creates_dir_if_missing` — 嵌套目录自动创建
  - `test_no_caching_picks_up_cwd_change` — 不缓存,响应 cwd 变化
  - `test_env_var_blank_falls_back_to_default` — 空字符串 env 不触发 override

### Code Quality

ruff 0 / mypy 0 / bandit 0

### Packaging

- `__version__` 1.6.2 → 1.6.3

---

## [1.6.2] — 2026-05-09

🐛 **Housekeeping + 修复 CI 6 连失败 + 全文档同步**

### 修复 CI(6 次连续失败的根本原因)

发现自 v1.4.9 起最近 6 次 GitHub Actions CI 全部失败。根因:

`TestSubdomainProgressFeedback` 类的 3 个测试只 mock 了 4 个旧源(crtsh / hackertarget / otx / certspotter),没 mock v1.4.8 加的 `subfinder` 和 v1.4.9 加的 `wayback`。CI 环境跑真实 wayback CDX API → 等 30s+ → 被 pytest-timeout 杀。

修复:用 `for name in gt.SUBDOMAIN_SOURCES: setitem(... lambda d: set())` 把所有源默认 stub 成空,然后只 override 需要返值的源。本地 + CI 都立即过。

### 全文档同步到 v1.6.2

之前 docs 大量 v1.4.6 / v1.4.9 stale 引用:

- README.md 徽章:tests 417→468, commands 9→10, version 1.4.9→1.6.2
- README.en.md 同步
- README 功能列表加 v1.5.0 (Diff/Batch) + v1.6.0 (邮箱 6 源) + v1.6.1 (进度审计)
- 工具对比表加 Diff/Batch 列
- TUTORIAL.md 加 ⑩ Diff + 批量章节
- docs/index.md(GitHub Pages 首页)全文重写到 v1.6.2

### GitHub repo 元数据同步

- 描述从"v1.4.6 / 9 commands / 417 tests"更新到"v1.6.2 / 10 commands / 468 tests / Diff / Batch / 6 free email sources"
- Topics 调整到 20(GitHub 上限):删 bilingual / pdf-report / certificate-transparency,加 dns-bruteforce / wayback-machine / batch-scan / diff-tool

### Tests

468 全绿(本地 + CI 都过 — CI 修复后首次绿)。

### Packaging

- `__version__` 1.6.1 → 1.6.2

---

## [1.6.1] — 2026-05-09

🐛 **进度条 100% 全功能审计 — 修复 3 处遗漏(用户反馈)**

### 背景

用户连续两次提问"是否所有功能每一步都加了进度条",要求 100% 仔细检查不许有遗漏。我对 12 个核心函数 + 6+6 个被动源逐一审计,发现 **3 处真实遗漏**:

### 修复 #1:domain-emails 阶段 2 子域名扫描静默

调 `enumerate_subdomains(show_progress=False)` 静默 1-2 分钟。改为透传 `show_progress`,子流程 4 阶段进度直接给用户看。

### 修复 #2:recursive_track_username profile 抓取阶段静默

递归扫描挖关联用户名时,会抓 8 个 profile 页面(每页 5s timeout,最坏 40s),期间完全静默。用户以为卡了。

加 3 层进度反馈:
- 进入新深度时:`深度 1/2:扫描用户名 'akxan_dev' ...`
- 抓 profile 阶段:`[fetch] 3/8 (当前已发现 2 个新候选)` 实时刷新
- 抓取完成后:`抽出 5 个新用户名:akxan, akxan_dev, akxan2, ...`

### 修复 #3:domain-emails 多 target 爬虫缺 [N/M] 标记

`include_subdomains=True` 时若找到 5 个 alive 子域,会逐个爬,但用户看不到"现在在第几个 target"。加 `[3/5] 爬取目标:api.example.com` 标记。

### 全功能进度审计结果(完整清单)

✅ 已齐全(无修):

- IP / Phone / WHOIS / MX / Email — 单次操作不需要
- track_username 主扫描 — _print_scan_progress
- enumerate_subdomains 全 5 阶段 — v1.4.11 时已加
- enumerate_domain_emails 阶段 1 (6 源并发) — 每源完成 log
- enumerate_domain_emails 阶段 3 (爬虫) — 每 10 页
- enumerate_domain_emails 阶段 4 (SMTP) — 每邮箱实时
- _run_subdomain_batch — `[N/M] 扫描 X` 标记
- diff_subdomain_results — 12ms 不需要
- 单源 _src_* 内部循环 — 不应单独打,与并发 log 交织混乱

❌ 修复(本版):

- recursive_track_username profile 抓取静默 → 加 3 层反馈
- domain-emails 阶段 2 子域名静默 → 透传 show_progress
- domain-emails 多 target 爬取缺序号 → 加 `[N/M]`

### 新增 i18n key(中英双语)

- `recursive.stage_scan` — 深度 N/M 扫描
- `recursive.stage_fetch` — 抓 N 个 profile
- `recursive.found_new` — 当前已发现 N 个
- `recursive.candidates_found` — 抽出 N 个新用户名
- `demails.target_progress` — `[N/M] 爬取目标:host`

### Tests

468 全绿(改动仅在进度反馈,核心逻辑未动,既有测试覆盖)。

### Packaging

- `__version__` 1.6.0 → 1.6.1

---

## [1.6.0] — 2026-05-09

✨ **域名邮箱挖掘:从 2 源 → 6 源 + 全并发,免费无注册**

### 背景

调研对标 theHarvester / Photon / EmailHarvester / EmailFinder / h8mail / holehe / Hunter.io 后,SpyEyes domain-emails 缺的就是"被动 API 多样性"和"SERP dorking"。这版补齐**完全免费 + 无需注册**的 4 个新源,顺序执行 → 全并发,总耗时 ≈ 最慢源(2-3 倍提速)。

### 新增 4 个免费数据源

#### 1. Bing SERP dorking(`_emails_from_bing`)

- 完全免费、无需 API key
- 用 `"@domain"` site/-site 双模式 dork,挖搜索引擎索引但你爬不到的页面里的邮箱
- User-Agent 伪装 + 500ms 延迟降低 captcha 风险
- 触发 captcha 自动 silent 跳过,不阻塞其他源

#### 2. DuckDuckGo HTML SERP(`_emails_from_ddg`)

- 用 `html.duckduckgo.com/html/` 端点(纯 HTML,无 JS,免登录)
- 比 Bing 对自动化更友好,几乎不触发反爬
- 三种查询变体(`"@domain"` / `"@domain" contact` / `"@domain" email`)分别挖

#### 3. Wayback Machine 历史归档(`_emails_from_wayback`)

- Internet Archive 的 CDX API 查 `*.<domain>` 历史归档过的 URL
- 优先抓 `contact / about / team / imprint / support / press / people / staff` 等高邮箱密度页面
- 限 50 个快照(防 wayback 限速)
- **核心价值**:挖出**已下线但归档过**的页面里的邮箱(crt.sh 没有,WHOIS 隐私后没有,爬虫拿不到)

#### 4. GitHub commit emails(`_emails_from_github`)

- GitHub Search API 查 `author-email:domain` 的公开 commits
- 未认证 rate limit 10 req/min,但单次 30 条结果就够了
- 可选 `SPYEYES_GITHUB_TOKEN` 环境变量提到 30 req/min(Personal Access Token,只读权限即可)
- **核心价值**:挖员工开发者的真实工作邮箱(他们 git push 到自家公开仓库时留下的)

### 性能 — 顺序 → 并发(2-3× 提速)

```python
# v1.5.0:顺序跑 2 源
crtsh (5s) → whois (3s) = 总 8s

# v1.6.0:并发跑 6 源
{crtsh, whois, bing, ddg, wayback, github} 同时启动
总耗时 = max(5s, 3s, 10s, 8s, 30s, 5s) = ~30s(瓶颈是 wayback)
比顺序累加(60s+)快 2× 以上
```

实测 `python.org`:
- 总耗时:**32 秒**(顺序累加估计 60-90 秒)
- 6 源全部跑完,任何一源失败 silent 降级
- 找到 `webmaster@python.org` ← Wayback 挖出来的(历史归档),crt.sh 完全没有

### 新设计:`DOMAIN_EMAIL_SOURCES` dict

与 `SUBDOMAIN_SOURCES` 同一架构哲学:

```python
DOMAIN_EMAIL_SOURCES = {
    'crtsh':   _emails_from_crtsh,
    'whois':   _emails_from_whois,
    'bing':    _emails_from_bing,    # v1.6.0
    'ddg':     _emails_from_ddg,     # v1.6.0
    'wayback': _emails_from_wayback, # v1.6.0
    'github':  _emails_from_github,  # v1.6.0
}
```

并发执行,任何一源失败 silent 跳过 + 落到 `errors` 字段。

### Tests

- 18 个新测试(共 **468 全绿**):
  - `TestDomainEmailNewSources` × 10:Bing/DDG/Wayback/GitHub 各源 + 失败处理 + 跨域过滤 + token 支持
  - `TestDomainEmailSourcesParallelism` × 2:并发执行 + 单源失败不影响其他

- 重构所有现有 `TestEnumerateDomainEmails` 测试用 `monkeypatch.setitem(DOMAIN_EMAIL_SOURCES, ...)` 模式

### Code Quality

ruff 0 / mypy 0 / bandit 0 / pytest 468 全绿

### Packaging

- `__version__` 1.5.0 → 1.6.0(进入 1.6 主线)

### 与 GitHub 同类工具对比定位

| 工具 | 数据源数 | 免费 | 注册 | 报告格式 |
|---|---|---|---|---|
| theHarvester | 30+(含商业) | 部分 | 多数需 | 1-2 |
| EmailHarvester | 7 SERP | ✅ | ❌ | 1 |
| EmailFinder | 5 商业 API | ❌ | ✅ | 1 |
| h8mail | 6 breach API | 部分 | ✅ | 1 |
| **SpyEyes v1.6.0** | **6**(全免费)| **✅** | **❌** | **8** |

**定位**:免费层最强、报告格式最丰富的中文 OSINT 邮箱枚举工具。

---

## [1.5.0] — 2026-05-09

✨ **三大新功能 + 4 工具全清的"硬性收官"版本**

### 新功能

#### 1. 子域名 Diff 模式(`spyeyes diff old.json new.json`)

OSINT 持续监控刚需 — 对比两次扫描挖出**新增 / 消失 / 状态变更**的子域。

```bash
spyeyes subdomain example.com --json > monday.json
# ... 几天后 ...
spyeyes subdomain example.com --json > friday.json
spyeyes diff monday.json friday.json   # 差异报告
spyeyes diff monday.json friday.json --save diff_report.html  # 8 种格式可导
```

输出结构(`_stats`):
- `added`:周二之前不在,周五新冒出来的子域
- `removed`:之前在但现在消失的(可能下线了)
- `changed`:host 仍在,但 IP / HTTP 状态 / Title 变了
- `unchanged`:完全一致(快速跳过)

字段对比包括:`alive / a / aaaa / cname / http_status / title`,**列表顺序无关**(`['1.1.1.1', '2.2.2.2']` 与 `['2.2.2.2', '1.1.1.1']` 视为同一)。

#### 2. 批量域名输入(`spyeyes subdomain --batch domains.txt`)

```bash
echo -e "example.com\nlinux.do\n# 注释行\nakxan.com" > targets.txt
spyeyes subdomain --batch targets.txt --batch-save-dir reports/ --alive-only
```

每个域独立扫描 + 独立报告,自动跳过 `#` 注释行 / 空行。`--batch-save-dir` 创建目录(若不存在)+ 每个域写 `subdomain_<domain>.html`(扩展名取 `--save` 或默认 `.html`)。

`--alive-only` 在 batch 模式下也对每个域独立生效。Ctrl+C 中断时显示"已完成 N/M",已跑的不丢。

#### 3. PyPI 构建产物 + twine 验证全过

`pyproject.toml` 配齐 setuptools build,本地 `python -m build` 产 wheel + sdist:

```
spyeyes-1.5.0-py3-none-any.whl   198K
spyeyes-1.5.0.tar.gz             245K
```

二者均通过 `twine check`。**实际上传 PyPI 需要你的 API token**:

```bash
twine upload dist/*
```

成功后任何人 `pip install spyeyes` 直接用。

### 代码质量(4 工具全清)

| 工具 | 状态 | 备注 |
|---|---|---|
| **ruff** | ✅ 0 issues | 全项目 + 测试 |
| **mypy** | ✅ 0 errors | 含新加的 diff/batch 函数完整类型注解 |
| **bandit** | ✅ 0 issues | B110/B112(silent 降级)加项目级 skip + 注释;B603(subprocess)加 nosec + 完整理由 |
| **pytest** | ✅ 456 passed | +13 新测试(`TestSubdomainDiff` × 8, `TestSubdomainBatch` × 5)|

### 修复

- `clear_screen()` 改用 ANSI 转义 `\033[2J\033[H` 替代 `os.system('cls'/'clear')` — 跨平台 + 无子进程 + 消除 bandit B605/B607 警告
- `diff_subdomain_results()` 显式类型收窄,host 必须是非空 str 才入 map(满足 mypy 严格类型检查)

### 性能(实测)

| 操作 | 时长 |
|---|---|
| 5000-vs-5000 host diff | **12 ms** |
| `_extract_hosts_from_body` 16KB body | **1.18 ms/call** |
| `_clean_subdomain_candidates` 10K hosts | **4.6 ms** |
| `_generate_bruteforce_candidates` (220 词) | **0.14 ms** |

### Packaging

- `__version__` 1.4.11 → 1.5.0(进入 1.5 主线 — 表明三大新功能 + 代码质量里程碑)

---

## [1.4.11] — 2026-05-09

✨ **HTTP probe 阶段进度条 + 提速 ~3×**(用户反馈"baidu.com 卡死不动")

### 背景

用户对大型域(baidu.com,1200+ 活跃子域)反馈"阶段 4/4 看不到进度,以为卡了"。实际是在跑,但阶段 4(HTTP probe)和 4b(JS extract)**没有进度反馈**,体感像死机。

### Fixes

#### 进度条 — 阶段 4 / 4b 都加上

之前只有阶段 3(DNS 解析)有进度条;阶段 4(HTTP probe)和 v1.4.9 加的 4b(JS extract 第二轮 DNS+probe)都是干等。现在:

- 阶段 4:`█████░░░░░░ 350/1203 (29.1%) 找到: 287` 实时刷新
- 阶段 4b DNS:`█████████░░ 80/94 (85.1%) 找到: 23`
- 阶段 4b probe:`██████░░░░ 15/23 (65.2%) 找到: 12`

#### 提速 — 三处合一,实测 ~3× 加速

| 改动 | 之前 | 现在 |
|---|---|---|
| HTTP probe worker 池 | 30(与 DNS 共享) | **80**(独立池,I/O bound 可高并发) |
| HTTP 总超时 | 5s | **4s** |
| HTTP connect 超时 | 与读超时共用 5s(死站要 5s 才放弃) | **拆出 2s**(死站 2s 即放弃) |

死站快速失败的效果(以 1203 个 host、含 30% 死站为例):

```
v1.4.10:  1203 / 30 workers × 5s = ~200s 最坏
v1.4.11:  1203 / 80 workers × 4s = ~60s 最坏 (含 2s connect 早失败)
                                    实测约 80s(含 stage 4b 二轮)
```

### 实测(`baidu.com`,完整流程 + JS 提取)

| 项 | v1.4.10 | v1.4.11 |
|---|---|---|
| 总耗时 | ~3 分钟 + 看着像卡死 | ~2 分钟 + 实时进度条 |
| 阶段 4 是否显示进度 | ❌ | ✅ |
| 体感 | "卡了?要不要 Ctrl+C?" | "在跑,89/1290 已 probe" |

### 配置

新增模块级常量(高级用户可改):

```python
SUBDOMAIN_HTTP_WORKERS = 80   # v1.4.11:HTTP probe 独立 worker 池
SUBDOMAIN_HTTP_PROBE_TIMEOUT = 4.0  # v1.4.11: 5.0 → 4.0
```

CLI 用户仍可 `--workers N --timeout S` 覆盖(`--workers` 现在仅控 DNS,HTTP probe 自动用 max(N, 80))。

### Tests

443 全绿(无新功能,仅性能/UX 改进,不需要新测试)。

### Packaging

- `__version__` 1.4.10 → 1.4.11

---

## [1.4.10] — 2026-05-09

✨ **`--alive-only` 现在也过滤导出报告**(用户反馈:bruteforce 后 dead 子域占满 HTML/PDF)

### Fixes / UX

之前 `--alive-only` flag 只影响终端打印,**导出的 HTML / PDF / JSON / CSV 报告仍含 dead 子域**(那时设计是"完整数据更有价值")。但 v1.4.9 加 bruteforce 后,小域名(如个人博客 `akxan.com`)的报告里 200+ dead 子域占满几屏,用户反馈"看着太卡而且占地方"。

**改动**:
- `--alive-only` 现在过滤 **CLI / JSON / 8 种导出报告全部**
- 数据 `_stats.total` 和 `_stats.alive` 保持原始值(让用户知道完整宇宙)
- 新增 `_filtered: {mode: 'alive_only', hidden: N}` 元数据字段(报告生成器可显示"已隐藏 N 个 dead 子域")
- 交互菜单(选项 `[8] 子域名枚举`)在保存前**额外加一问** "是否隐藏不可达子域?",默认是

### CLI

```bash
# 现在三种使用全部过滤 dead:
spyeyes subdomain example.com --alive-only --save report.html  # 报告中只有 alive
spyeyes subdomain example.com --alive-only --save report.pdf
spyeyes subdomain example.com --alive-only --json | jq '.subdomains'

# 不传 --alive-only 时保持原行为(完整数据)
```

### Tests

- 8 个 `TestSubdomainCli` 测试(+3 新):
  - `test_alive_only_filters_json_output` — JSON 含 alive,带 `_filtered` 元数据,`_stats` 保留原值
  - `test_alive_only_filters_saved_report` — HTML 写出文件中**确实**没 dead 子域
  - `test_alive_only_disabled_keeps_full_data` — 不传 flag 时向后兼容
- **共 443 全绿**

### Packaging

- `__version__` 1.4.9 → 1.4.10

---

## [1.4.9] — 2026-05-09

✨ **子域名收集三大新维度** — Wayback Machine + DNS 字典爆破 + JS/HTML host 提取

### Features

#### 1. Wayback Machine 历史归档源(自动启用)

- 新加 `_src_wayback`,加入 `SUBDOMAIN_SOURCES` 第 6 源
- 调 `web.archive.org/cdx/search/cdx?url=*.{domain}` CDX API,聚合 Internet Archive 自 1996 年起所有归档过的 URL
- 用途:挖出**已下线但曾出现过**的子域(被动 DNS / CT 已过期不会留)
- `limit=10000` 防大型域刷爆,`collapse=urlkey` 自动去重
- 对 429 / 5xx / 超时 silent 返空,不污染其他源

#### 2. DNS 字典爆破(opt-in)

- 新加 `_generate_bruteforce_candidates(domain)` 生成器
- 内置 ~220 个高命中率前缀字典(jhaddix top-1k 精选子集):
  - 基础:`www / mail / ftp / smtp / pop / imap / api / app / admin / dev / staging / test / prod / qa / sandbox / beta`
  - 服务:`vpn / git / jenkins / jira / grafana / kibana / prometheus / db / redis / mongo`
  - 业务:`shop / store / pay / billing / login / signup / portal / partner / event`
  - 地理 / 编号:`m / mobile / ws / cdn / cdn1 / cdn2 / web1 / web2 / dev1 / dev2`
- 启用方式(三选一):
  - CLI flag:`spyeyes subdomain example.com --bruteforce`
  - 环境变量:`SPYEYES_BRUTEFORCE=1 spyeyes subdomain example.com`
  - 交互菜单:第二个 prompt 选 `[2] 是`
- **自定义字典**:`SPYEYES_DNS_WORDLIST=/path/to/big.txt` 覆盖内置(支持注释行 `#` + 空行,massdns/shuffledns 字典直接复用)
- 字典 prefix 直接拼成 `<prefix>.<domain>` 加入 candidates,通过现有 stage 3 DNS 解析自动验证,死的自然过滤
- `_stats.bruteforce_added` 字段统计字典新引入的 host 数

#### 3. JS / HTML body host 提取(默认启用)

- 修改 `_probe_one_subdomain` 接受 `parent_domain` 参数
- HTTP probe 抓 `<title>` 时,顺带正则扫已读的 16KB body,提取 `*.parent_domain` 的 hostname 引用
- 用例:
  - 内联 script 中的 API endpoint:`fetch('https://api.example.com/v1/users')`
  - 资源 src/href:`<script src="//cdn.example.com/lib.js">` / `<a href="https://blog.example.com/...">`
  - SPA 网站硬编码的 backend 域
- 提取后跑第二轮 DNS + probe(单轮即止,不递归扩张)
- 截断到 `SUBDOMAIN_MAX_RESULTS` 防恶意页面塞几千个无关 host
- `_HTML_HOSTNAME_RE` 正则 + 跨域过滤,自动剔除 `googletagmanager.com / attacker.com` 等外域引用
- 关闭方式:`--no-js-extract`(几乎免费,默认开)
- `_stats.js_extracted` 字段统计 JS 提取新发现的 host 数

### CLI 改动

新增 `subdomain` 子命令两个参数:
```
--bruteforce        Enable DNS dictionary bruteforce (~220 prefixes; SPYEYES_DNS_WORDLIST=path 覆盖)
--no-js-extract     Skip JS/HTML body extraction (default: enabled)
```

### 实测对比(`anthropic.com`)

| 配置 | 总 host 数 | alive | 时间 |
|---|---|---|---|
| v1.4.8(5 源) | 207 | ~50 | ~3s |
| v1.4.9 默认(6 源 + JS 提取) | 207 + 内嵌引用 | ~55 | ~5s |
| v1.4.9 `--bruteforce`(6 源 + 字典 + JS) | 207 + 220 字典 + 引用 | ~60 | ~12s |

### Tests

- 18 个新测试,共 **440 全绿**(0 红):
  - `TestPassiveSources::test_wayback_*` × 4(parses / empty / rate-limit / in dict)
  - `TestBruteforce` × 4(builtin / empty / custom wordlist / fallback)
  - `TestJsExtract` × 5(inline / attribute / cross-domain / empty / OOM cap)
  - `TestEnumerateSubdomains::test_bruteforce_*` × 3(flag / off / env var)
  - `TestEnumerateSubdomains::test_js_extract_*` × 2(finds new / disabled)

### Packaging

- `__version__` 1.4.8 → 1.4.9

---

## [1.4.8] — 2026-05-09

✨ **可选集成 ProjectDiscovery `subfinder`**(自动检测 + 30+ 数据源接力)

### Features

- 新增 `_src_subfinder` 作为子域名第 5 个数据源:
  - 模块加载时一次性 `shutil.which('subfinder')` 检测,缓存结果(无 subfinder 时零开销)
  - 调 `subfinder -d <domain> -silent -json` JSON Lines 输出
  - 每行 `{"host":"...","input":"...","source":"..."}` 解析,跨域条目自动过滤
  - 30s 单源超时 + 90s 总超时硬限,失败 silent 返 `set()`(不污染其他源)
  - 自动继承用户 `~/.config/subfinder/provider-config.yaml` 中的 30+ API key(virustotal、shodan、censys、binaryedge、chaos、bevigil、bufferover、dnsdumpster、digitalyama、fofa、fullhunt、hunter、leakix、netlas、quake、rsecloud、redhuntlabs、securitytrails、shodan-idb、whoisxmlapi、zoomeye 等)
- `SUBDOMAIN_SOURCES` dict 加 `'subfinder': _src_subfinder`,与原 4 源(crtsh/certspotter/hackertarget/otx)并行执行
- 自动检测 = 用户没装 subfinder 完全无感知,装了立即接力使用,无需任何配置代码改动

### 安装方式(可选,推荐)

```bash
# macOS
brew install subfinder

# Linux
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 配置 ProjectDiscovery PDCP key 解锁更多源
export PDCP_API_KEY="your-pdcp-key"
```

### 实测对比

```
=== 5 源全测 anthropic.com ===
  crtsh         ->     0 hosts in   291ms (临时数据源问题)
  certspotter   ->    50 hosts in   830ms
  hackertarget  ->    50 hosts in   594ms
  otx           ->     0 hosts in   475ms (临时)
  subfinder     ->   207 hosts in  1751ms  ✨ 新增 — 4倍于其他源上限
```

### Tests

- 加 5 个 subfinder 测试(共 422 全绿):
  - `test_subfinder_no_binary_returns_empty` — 没装时静默返空
  - `test_subfinder_parses_json_output` — JSON Lines 解析 + 跨域过滤
  - `test_subfinder_timeout_returns_empty` — 超时不抛
  - `test_subfinder_nonzero_exit_returns_empty` — 非零退出码不抛
  - `test_subfinder_in_sources_dict` — 已注册到 SUBDOMAIN_SOURCES

### Packaging

- `__version__` 1.4.7 → 1.4.8

---

## [1.4.7] — 2026-05-09

✨ **CertSpotter 支持 API key**(对齐 OTX 设计 — 免费注册即可解锁高 quota)

### Features

- `_src_certspotter` 加 `SPYEYES_CERTSPOTTER_API_KEY` 环境变量支持:
  - 无 key:免费匿名层 100 req/h
  - 有 key:免费注册 https://sslmate.com/account/api_credentials,quota 显著放宽
  - 用 `Authorization: Bearer {key}` header

### 配置示例

```bash
# 在 ~/.zshrc / ~/.bashrc 中加:
export SPYEYES_OTX_API_KEY="..."           # AlienVault OTX 免费 key
export SPYEYES_CERTSPOTTER_API_KEY="..."   # SSLMate CertSpotter 免费 key
export SPYEYES_PHONE_API_KEY="numverify:..." # 可选实时 HLR 电话运营商
```

### 实测

`linux.do` 4 源:certspotter(with key) 1.5s 返 36 hosts;OTX(with key) 26s 返 23 hosts。

### Packaging

- `__version__` 1.4.6 → 1.4.7

---

## [1.4.6] — 2026-05-09

✨ **HTML 报告交互性 + 可读性升级**(用户反馈)

### Features

- **🔝 表头粘性(sticky thead)** — 长列表(165+ 子域)滚动时表头始终可见
  - `th{position:sticky;top:0;z-index:5}` + box-shadow 模拟"压在内容之上"层次感
- **🔗 所有主机名都可点击**(包括 dead 子域)
  - 之前仅 alive 子域有 href,dead 子域只是文本
  - 现在所有 host 默认 `https://{host}/` 链接,用户可直接点击尝试访问
  - alive 用 probe 时探测到的真实 scheme,dead 默认 https
- **🟢 alive / 🔘 dead 视觉区分**:
  - `tr[data-alive="true"]` 左边框 3px 暗绿 `#1f5837`
  - `tr[data-alive="false"]` 左边框 3px 灰 `#c8c1ad` + 整行字体 `--muted` 弱化
  - 一眼区分活跃和不活跃子域
- **🎨 HTTP status 颜色编码**:
  - 2xx:`--success` 暗绿(粗体)
  - 3xx:`--link` 古典蓝
  - 4xx:`--warn` 暗金
  - 5xx:`--accent` 印章红
- **行 hover 加强**:`box-shadow:inset 0 0 0 0.5px var(--ink)` 显示边框

### Tests

- `TestSubdomainReports::test_html_renders_anchor_for_alive` 改成
  `test_html_renders_anchor_for_all_hosts` — 验证 alive + dead 都有 href
  + `data-alive="true"/"false"` 属性
- 417 测试全绿
- ruff/mypy 全清

### Packaging

- `__version__` 1.4.5 → 1.4.6

---

## [1.4.5] — 2026-05-09

🐛 **HTML 报告大屏太窄 + 长主机名变阶梯式**(用户反馈)

### Bug Fix

用户截图显示 baidu.com 报告中 `abot.pos.baidu.com`(19 字符)被压成 3 行阶梯,
2K 大屏左右大量留白浪费。

修复:
- **`max-width` 920px → 1280px**(给桌面足够空间)
- **`td:first-child{white-space:nowrap}`** — host 列永远完整一行,不再阶梯式
- **`@media(max-width:1340px){body{max-width:none;margin:2em 4em 3em}}`** — 窄屏让出 max-width 限制
- **`@media(max-width:900px){td:first-child{white-space:normal}}`** — 移动端允许 host 换行避免横向溢出
- 移动端 `@media(max-width:720px)` margin 收紧到 `1em` + padding 收紧到 `0 1em 2em`
- `td` 加 `overflow-wrap:anywhere` 让 IPv6 等极长串可断

### 测试

- 417 测试全绿
- ruff/mypy 全清

### Packaging

- `__version__` 1.4.4 → 1.4.5

---

## [1.4.4] — 2026-05-09

🚨 **紧急修复 + 报告美化补完 — Editorial Investigation Brief 全套**

### 🎨 Visual — XMind 重做层级展开

用户反馈:之前 XMind 节点信息密度过高(host + 4 IP + status 一行),且 `<title>:`
看着像 HTML 残留 bug。重做 subdomain 分支:

- **host 节点只显示 host + status code**(不再塞 IP)
- **IPv4 / IPv6 各占独立一层子节点**(`📡 IPv4 (N)` / `📡 IPv6 (N)`,各下挂 IP 列表)
- **CNAME 单独一层**:`🔗 CNAME → ...`
- **Title 改用 `📄 标题:` / `📄 Title:`**(不再用 `<title>:` 像 HTML bug)
- **概要节点**`📊 共发现 N · 活跃 M · 来自 K 数据源`提前显示
- alive `flag-green` ✓ / dead `task-start` ✗ 视觉分级清晰

收起时简洁,展开看详细 — 真正利用 XMind 思维导图层级特性。

### 🎨 Visual — Graph 改浅色

用户反馈不要深色背景。Graph 改回 Editorial 风浅色 theme:

- 背景:cream `#fafaf5`(替代之前的 dark `#0e0e12`)
- 节点配色:**印章红 `#c8102e`**(主节点)+ **古典蓝 `#1d4ed8`**(命中)+ 暗灰(其它)
- 节点 stroke 用 `surface white` + drop-shadow 替代 dark theme 的 glow
- header 用 cream 半透明 + 5px 双线分隔(同 HTML 报告)
- text stroke 用 cream outline 在浅色 svg 上对比好

### 🎨 Visual — PDF 内页美化

用户反馈"不能只加封面页就够了,第二页内容也要美化"。重做:

- **Heading2** 字号 17pt,leading 22pt,spaceBefore 22pt(更明显的章节起点)
- **Heading3** 字号 12pt,文字色用印章红 `#c8102e`(章节副标题感)
- **`_pdf_table_style` 重做 — Editorial 报刊表格风**:
  - 表头 cream `#e8e3d6` 浅底色 + 顶部 1.2pt 主线 + 底部 0.5pt 细线
  - 末行底部 1.2pt 主线(报刊双线感)
  - 数据行无垂直线(只留水平分隔 0.25pt)
  - 斑马纹 cream/white 交替
  - padding 8pt(表头)/ 6pt(数据),数据有呼吸感

### 🎨 PDF 页脚字符间距 + 去封面冗余链接

(详细见同次发布的早期 commit 段)

### 🐛 Bug Fixes — 子域名查询(P0,**功能性故障**)

用户报告"子域名查询都是 0",systematic-debugging 实测 4 个被动源真实状态:

| 源 | 现状 | 处理 |
|---|---|---|
| **ThreatCrowd** | 域名 `www.threatcrowd.org` 已**无 DNS 记录**(网站死了) | **移除** |
| **AlienVault OTX** | 匿名访问被限速 `429 Anonymous limited`(API 政策变了) | 加 `SPYEYES_OTX_API_KEY` env var 支持 |
| **HackerTarget** | 匿名免费 quota 用完后返 `API count exceeded` | 不可控(用户侧) |
| **crt.sh** | `.do` / 其它特殊 TLD 需要 25-30s 才返回,`SUBDOMAIN_SOURCE_TIMEOUT=15s` 不够 | timeout 加大到 45s |

修复:
- **删除 `_src_threatcrowd`**(死站)
- **新增 `_src_certspotter`**(SSLMate CertSpotter API,免费 CT 日志,替补 crt.sh)
  - 实测 linux.do 拉到 36 个候选(crt.sh 50 个 + certspotter 36 个 ≈ 60+ 独立子域)
- **OTX 加 API key 支持**:`SPYEYES_OTX_API_KEY=YOUR_KEY` env var,
  发 `X-OTX-API-KEY` header(免费注册 https://otx.alienvault.com)
- `SUBDOMAIN_SOURCE_TIMEOUT` 15s → 45s

实测 `linux.do` (`.do` TLD) **从 0 个 → 60+ 个子域**。

### 🐛 Bug Fixes — PDF(P1,**视觉问题**)

用户截图显示:
1. **页脚 `SPYEYES▲ OSINT 调查工具` 字符间距过紧**
   - 根因:之前用 `font_name`(STSong-Light 中文字体,Latin advance 偏窄)
   - 修复:页脚 canvas 改用 `Helvetica`,纯英文 brand `SpyEyes  ·  OSINT Toolkit`(中英版统一)
   - bonus:页脚加 query 作为 running header 居中
2. **封面页冗余项目链接** `spyeyes ▲ github.com/Akxan/SpyEyes`(用户嫌弃)
   - 修复:删除
3. **PDF 生成失败 `'Canvas' object has no attribute 'setCharSpace'`**
   - 根因:`setCharSpace` 是 reportlab textObject 方法不是 Canvas 直接方法
   - 修复:删除该调用(Helvetica 间距已自然)

### 🧪 Tests

- **TestSubdomainParsers**:`test_threatcrowd_parses_subdomains` → 改成 `test_certspotter_parses_dns_names`(新源 + 跨域过滤验证)
- **TestPassiveCollectSubdomains** / **TestEnumerateSubdomains** / **TestSubdomainStageProgress**:把 `'threatcrowd'` 引用全改为 `'certspotter'`
- 417 测试全绿
- ruff / mypy 全清

### 📦 Packaging

- `__version__` 1.4.3 → 1.4.4

---

## [1.4.4 早期 — 已合并到上方] — 2026-05-09

### 🐛 Bug Fixes — 子域名查询(P0,**功能性故障**)

用户报告"子域名查询都是 0",systematic-debugging 实测 4 个被动源真实状态:

| 源 | 现状 | 处理 |
|---|---|---|
| **ThreatCrowd** | 域名 `www.threatcrowd.org` 已**无 DNS 记录**(网站死了) | **移除** |
| **AlienVault OTX** | 匿名访问被限速 `429 Anonymous limited`(API 政策变了) | 加 `SPYEYES_OTX_API_KEY` env var 支持 |
| **HackerTarget** | 匿名免费 quota 用完后返 `API count exceeded` | 不可控(用户侧) |
| **crt.sh** | `.do` / 其它特殊 TLD 需要 25-30s 才返回,`SUBDOMAIN_SOURCE_TIMEOUT=15s` 不够 | timeout 加大到 45s |

修复:
- **删除 `_src_threatcrowd`**(死站)
- **新增 `_src_certspotter`**(SSLMate CertSpotter API,免费 CT 日志,替补 crt.sh)
  - 实测 linux.do 拉到 36 个候选(crt.sh 50 个 + certspotter 36 个 ≈ 60+ 独立子域)
- **OTX 加 API key 支持**:`SPYEYES_OTX_API_KEY=YOUR_KEY` env var,
  发 `X-OTX-API-KEY` header(免费注册 https://otx.alienvault.com)
- `SUBDOMAIN_SOURCE_TIMEOUT` 15s → 45s

实测 `linux.do` (`.do` TLD) **从 0 个 → 60+ 个子域**。

### 🐛 Bug Fixes — PDF(P1,**视觉问题**)

用户截图显示:
1. **页脚 `SPYEYES▲ OSINT 调查工具` 字符间距过紧**
   - 根因:之前用 `font_name`(STSong-Light 中文字体,Latin advance 偏窄)
   - 修复:页脚 canvas 改用 `Helvetica`,纯英文 brand `SpyEyes  ·  OSINT Toolkit`(中英版统一)
   - bonus:页脚加 query 作为 running header 居中
2. **封面页冗余项目链接** `spyeyes ▲ github.com/Akxan/SpyEyes`(用户嫌弃)
   - 修复:删除
3. **PDF 生成失败 `'Canvas' object has no attribute 'setCharSpace'`**
   - 根因:`setCharSpace` 是 reportlab textObject 方法不是 Canvas 直接方法
   - 修复:删除该调用(Helvetica 间距已自然)

### 🧪 Tests

- **TestSubdomainParsers**:`test_threatcrowd_parses_subdomains` → 改成 `test_certspotter_parses_dns_names`(新源 + 跨域过滤验证)
- **TestPassiveCollectSubdomains** / **TestEnumerateSubdomains** / **TestSubdomainStageProgress**:把 `'threatcrowd'` 引用全改为 `'certspotter'`
- 417 测试全绿
- ruff / mypy 全清

### 📦 Packaging

- `__version__` 1.4.3 → 1.4.4

---

## [1.4.3] — 2026-05-09

🐛 **两个用户报告问题修复** —— 子域名 cold start 返 0 + PDF 标题与 subtitle 重叠。

### 🐛 Bug Fixes

- **子域名查询 cold start 返 0(P0)** — 用户每次新进程跑 `spyeyes subdomain X` 都返 0
  - **根因**:`safe_get` 把 connect timeout 强制 cap 到 `min(3.0, timeout)`(为 username 扫描场景设计的"快踢死慢 host")。但 crt.sh 等 OSINT 源**首次 TLS 握手就要 5+s** → 3s connect 必超时 → silent 返 None → 4 个被动源全 0
  - **诊断证据**:`_src_crtsh('anthropic.com')` 单调返 119 host(6.6s);`enumerate_subdomains` 第一次调返 0;同一进程内紧接着第二次调返 117(connection pool 复用绕过 cold start)
  - **修复**:`safe_get` 加 `connect_timeout: Optional[float] = None` 参数,显式覆盖 connect 上限。OSINT 慢源(5 处 `_src_*` + 1 处 `_emails_from_crtsh`)传 `connect_timeout=10.0`
  - 验证:fresh process 跑 `subdomain anthropic.com` 现在返 119 个候选(包含 `cdn.anthropic.com`/`api.anthropic.com` 等)
- **PDF 大标题与 subtitle 重叠(P1)** — 用户截图显示 "SpyEyes 报告" 大字号下方 subtitle 重叠不可读
  - **根因**:大标题用 `<font size="32">` inline tag 但 wrapping `ParagraphStyle` 是 `styles['Normal']`(`leading=13`)。32pt 字符高度溢出 13pt box → 下个 element 紧贴原位置渲染 → 视觉重叠
  - **修复**:专门定义 `CoverTitle` ParagraphStyle(`leading=42`,与 32pt fontSize 配套)+ `CoverSubtitle` ParagraphStyle(`leading=14`),用 `spaceAfter` 控间距,不再依赖 spacer
  - 验证:pypdf 文本提取确认大标题与 subtitle 各自独立成行,中英两版双语正常

### 🧪 Tests

- 417 测试全绿(无新测试,通过现有 PDF 报告生成测试覆盖回归)
- ruff / mypy 全清

### 📦 Packaging

- `__version__` 1.4.2 → 1.4.3

---

## [1.4.2] — 2026-05-09

🎨 **PDF + XMind 美化补完** —— v1.4.1 漏的两种格式同款 Editorial Investigation Brief 调性。

### 🎨 PDF 大改

- **独立封面页**(第一页 PageBreak 后才进数据):
  - 80pt 上空白 + CONFIDENTIAL 印章(2px 红色边框 Table)+ 大号标题(`<font size="32">`)
  - 双语 classification:zh `机密 · OSINT 简报` / en `CONFIDENTIAL · OSINT BRIEF`
  - 双语 subtitle:zh `开源情报调查档案` / en `OPEN-SOURCE INTELLIGENCE DOSSIER`
  - 双线 HRFlowable(2px + 0.5px)章节装饰
  - 元数据三列表:`命令 / 查询 / 生成时间`,标签 7pt 灰色 uppercase + 值 9.5pt 加粗
  - 底部品牌链接 `spyeyes · github.com/Akxan/SpyEyes`
- **每页底部页脚**(`onFirstPage` + `onLaterPages` callback):
  - 0.3px 横线分隔 + 左下品牌 `SPYEYES · OSINT 调查工具` / `SPYEYES · OSINT TOOLKIT`
  - 右下页码 `p. N`(7pt 灰色 mono)
- **更对比鲜明的字号 hierarchy**:
  - Title 32pt(封面)/ Heading2 15pt / Heading3 12pt / Normal 9.5pt
  - leading 加大让 STSong-Light 中文字符不挤
- 引入 `HRFlowable` + `PageBreak`(reportlab.platypus)

### 🎨 XMind 大改

- **`<marker-refs>` XMind 内置图标系统**(让 XMind 8 渲染时节点视觉分级清晰):
  - root 节点:`star-red`(红五角星强调)+ emoji prefix 按 cmd 区分
    (`🌐 ip` / `📱 phone` / `👤 username` / `🔍 whois` / `📧 mx` / `🧬 permute` / `🌐 subdomain` / `📧 domain-emails`)
  - 错误节点:`flag-red` + `symbol-warning`
  - **username**:类别分组 `flag-blue`,命中平台 `task-done`(绿勾)
  - **permute_scan**:有命中变形 `flag-purple`,空命中 `flag-orange`,命中平台 `task-done`
  - **mx**:节点 `symbol-tip`,records 按 preference 数字映射 `priority-1..9`
  - **domain-emails**:passive `flag-blue` + `symbol-info`,crawl `flag-green` + `symbol-attention`,
    pattern `flag-purple` + `symbol-question`;verified ✓ → `task-done`,unverified ✗ → `flag-red`
  - **subdomain**:status code 映射 — 2xx `task-done`,3xx `task-3quar`,
    4xx `flag-orange`,5xx `flag-red`;wildcard 警告 `symbol-warning + flag-red`
  - **wildcard 警告**:`symbol-warning + flag-red`(双图标视觉冲击)
- **元数据 child topic**(每报告独立 `⏱ 生成时间: ...` 子节点)— XMind 单行 title 限制下,
  把元数据外提到独立 child 让 root 简洁
- root title:`{emoji} {报告名} · {cmd} · {query}` 简短易读
- sheet title:`{报告名} — {query}`(XMind 8 会显示在 tab)

### 🌍 Bilingual

- 中英两版 PDF / XMind 都美观:
  - 印章风:`机密 · OSINT 简报` ↔ `CONFIDENTIAL · OSINT BRIEF`
  - subtitle:`开源情报调查档案` ↔ `OPEN-SOURCE INTELLIGENCE DOSSIER`
  - 页脚品牌:`SPYEYES · OSINT 调查工具` ↔ `SPYEYES · OSINT TOOLKIT`

### 🧪 Tests

- 417 测试全绿(无新测试,通过现有报告生成测试覆盖)
- ruff / mypy / bandit 全清
- pypdf 验证 2 页结构 + 封面页文字提取确认双语正确

### 📦 Packaging

- `__version__` 1.4.1 → 1.4.2

---

## [1.4.1] — 2026-05-09

🎨 **报告美化 — Editorial Investigation Brief 风格**(调查档案/报刊调性)。
设计哲学:**专业 + 沉稳 + 技术感**,让客户/老板看到觉得"是真做调查"。

### 🎨 Visual Redesign

- **HTML 报告全面重写** — 从默认 Helvetica/sans-serif 升级到 editorial 印刷品风格:
  - **字体三件套**:Cormorant Garamond(衬线 display)+ Crimson Pro(衬线 body)
    + JetBrains Mono(等宽 data),CJK fallback 用 Noto Serif SC + Sarasa Mono SC
  - **配色**:cream `#fafaf5` 背景 + ink `#0a0a0c` 印墨 + 印章红 `#c8102e` + 古典蓝 `#1d4ed8`
    (避免 AI 千篇一律的 purple gradient / 圆角阴影 / 卡片层叠)
  - **Masthead 报刊头**:5px 双线分隔 + CONFIDENTIAL · OSINT BRIEF 印章徽章(`-1.5deg` 倾斜)
    + 大号衬线标题 + tracking-spaced subtitle
  - **Meta strip**:CSS Grid `auto-fit minmax(180px,1fr)`,3 列元数据(命令/查询/生成时间)
    自适应布局
  - **Section h2**:罗马数字章节编号(I/II/III)用 `counter-reset` 自动累加
  - **Tables**:1.5px 双线 frame + zebra row + 衬线表头 + 等宽 mono 数据 + hover 过渡
  - **Colophon footer**:小号 mono 大写字距,谦虚得体
  - **响应式**:`@media(max-width:720px)` 移动端字号缩小 + padding 减少
  - **Print stylesheet**:`@media print` 让打印输出保留排版骨架
- **D3.js Graph 报告深色专业 theme**:
  - 暗色背景 radial gradient `#0e0e12 → #08080c`(替代之前 `#fafafa`)
  - 节点配色金/蓝/灰:主节点金色 `#d4af37` 配 drop-shadow 光晕,命中蓝 `#4a9eff`,其它暗灰
  - 节点 hover 时光晕加强(filter: drop-shadow 14px),增加交互反馈
  - 主节点用衬线字体显示(`<g[data-group="1"]> text` 选择器)+ 金色下划线
  - Header 加 backdrop-filter blur + radial gradient 半透明,不阻挡画布
  - Legend 圆点用 `box-shadow: 0 0 8px currentColor` 发光效果
  - "情报关系图谱" / "Intelligence Graph" eyebrow + Cormorant 衬线大标题
  - 右下角 SpyEyes 隐式签名(pointer-events: none)
- **TXT 报告 ASCII 装饰边框**(像电传报告):
  - 双线 box-drawing characters(`╔═╗║╚═╝`)框出 70 字符宽标题块
  - 标题 + classification 两行居中
  - 元数据用 `│` 竖线分隔,`>10` 右对齐字段名
  - 装饰横线 `─` × 66 划开 header / body
- **Markdown 报告 frontmatter + 紧凑元数据表**:
  - YAML frontmatter(Jekyll/Hugo/Obsidian 兼容):`title / command / query / generated / tool / classification`
  - `# 标题` + `> _机密 · OSINT 简报_` 引文式 classification
  - 元数据从竖列改为单行 3 列 markdown 表(更紧凑)

### 📐 Design Principles

- **不用** AI 设计常见 cliche:无 purple/pink gradient、无圆角卡片阴影、
  无 emoji 滥用、无 system font(Inter/Roboto/Helvetica/Arial)
- **用**:衬线字体(Cormorant/Crimson)+ 等宽字体(JetBrains Mono)+ CJK 衬线(Noto Serif SC)
- **章节装饰**:罗马数字编号(I/II/III)+ 印章式徽章 + 5px 双线 horizontal rule
- **Mono 用于数据**(IP / hostname / 邮箱 / status code 列对齐)
- **Serif 用于标题**(elegant 调查报告调性)

### 🌍 Bilingual

- 中英两版都美观:中文 UI 用"机密 · OSINT 简报"+ "开源情报调查档案" subtitle,
  英文用 "CONFIDENTIAL · OSINT BRIEF" + "Open-Source Intelligence Dossier"
- 字体 fallback chain:Cormorant Garamond → Noto Serif SC(中文)→ 系统字体兜底
- 所有装饰文案双语

### 🧪 Tests

- 417 测试全绿(更新 1 个 markdown 测试断言适配新 frontmatter 结构)
- ruff / mypy / bandit 全清

### 📦 Packaging

- `__version__` 1.4.0 → 1.4.1

---

## [1.4.0] — 2026-05-09

📧 **新增域名邮箱枚举(OSINT email harvest)** —— 第 9 个核心 OSINT 能力。设计哲学"全 + 准":多源被动 + 深度爬取 + 含 alive 子域,默认开;高调动作(SMTP 验证)opt-in。

### ✨ Features

- **`spyeyes domain-emails example.com` 子命令** —— 类 theHarvester + Hunter.io 混合:
  - **被动多源(默认全开)**:
    - crt.sh CT 日志 SAN/email 字段(`_emails_from_crtsh`)
    - WHOIS 注册联系人(`_emails_from_whois`)
  - **深度爬取(默认开 + 含 alive 子域)**:
    - robots.txt 解析 + 默认遵守 Disallow(`--ignore-robots` opt-out)
    - sitemap.xml 提取(`<loc>` 标签 + 一层嵌套 sitemap index)
    - 内部链接 BFS 递归(默认深度 5,最多 500 页)
    - 单域 500ms 速率限制(防 IP 被封反而拿不到)
    - 优先路径补充种子:`/contact /about /team /imprint /privacy ...`
    - 复用 `enumerate_subdomains` 拿 alive 子域,逐个爬(`--no-include-subdomains` 关闭)
  - **模式生成(opt-in `--guess "John Doe,Jane"`)**:
    - 10 种 Hunter.io 风格模式:`firstname.lastname` / `f.lastname` / `firstname` / `lastname` / `fl` 等
    - 输入 `John Doe, Jane Smith` 多人逗号分隔
  - **SMTP 验证(opt-in `--verify-smtp`)**:
    - HELO + MAIL FROM + RCPT TO 探测,250 = 存在,550/551/553 = 不存在
    - 强制 disclaimer "仅对自己拥有的域使用"
- **4 阶段实时反馈**(沿用 v1.3.3 stage 风格):
  - 阶段 1/4:被动数据源 → `[crtsh]` `[whois]` 各自候选数
  - 阶段 2/4:发现 alive 子域(显示爬取目标数)
  - 阶段 3/4:深度爬取(实时 pages/emails/queue 进度,每 10 页刷新)
  - 阶段 4/4:SMTP 验证(逐个 ✓/✗ 显示)
- **输出按 source 分组**(passive / crawl / pattern):
  - 终端打印高亮 ✓ verified / ✗ unverified / 出处页面 URL
  - 8 种报告全支持:Markdown 表 / HTML mailto: 链接 / PDF / TXT / CSV 4列 / XMind 三分支(passive/crawl/pattern)/ Graph 力导向图(domain 中心 + 邮箱节点按 source 着色)/ JSON
- **交互菜单 `[ 9 ]` 域名邮箱枚举**(语言切换从 [9] 让位到 [10])
- **历史记录**:`history` 列出 domain + 邮箱总数 + 爬取页数 + 验证数

### 🔒 Security

- **跨域过滤**:`_is_email_relevant` 仅接受 target 或子域邮箱(crawl 偶尔抓到第三方邮箱直接丢)
- **占位域名黑名单**:`yourdomain.com` 等(target 自己若是占位符则不过滤,允许真实测试)
- **正则 lookbehind**:`(?<![a-zA-Z0-9._%+-])` 防 `prefixabc@x.com` 被截成 `abc@x.com`
- **robots.txt 默认遵守**(opt-out)— 礼貌爬虫,降低被反爬墙拒概率反而拿到更多数据
- **速率限制 500ms**(不可调)— 防爬虫拉黑
- **总超时 5 分钟**(可调) + 单页 10s + body 256KB 早停 — 防大站把进程拖死
- **SMTP 验证 opt-in + 强 disclaimer** — 仅对自己拥有/授权域使用

### 🧪 Tests

- **+41 个新测试**(全套 376 → 417):
  - `TestEmailRelevance` × 7:跨域过滤、子域、占位符
  - `TestEmailExtractFromText` × 6:mailto / regex / lookbehind / Unicode / 空输入
  - `TestEmailPatternGeneration` × 5:单姓名/多姓名/dedup/Unicode
  - `TestRobotsTxt` × 3:解析 + Disallow 匹配
  - `TestSitemapParsing` × 1:`<loc>` 跨域过滤
  - `TestEmailsFromCrtsh` × 2:多字段 + 异常响应
  - `TestEnumerateDomainEmails` × 6:invalid 拒、被动 only、完整流程、模式生成、SMTP off/on
  - `TestDomainEmailsCli` × 3:argparse + 全 flag + run_cli
  - `TestDomainEmailsReports` × 7:8 种格式不崩 + 关键内容
  - `TestDomainEmailsI18n` × 1:19 个新键中英完整
- ruff / mypy / bandit 全清

### 📦 Packaging

- `__version__` 1.3.3 → 1.4.0
- `pyproject.toml` description 加 "Domain emails enumeration"

### ⚠️ 使用合规提醒

- 默认行为(被动 + robots.txt 遵守)合法、礼貌
- `--ignore-robots` / `--verify-smtp` 高风险,仅对自己拥有或获得授权的域使用
- SpyEyes 项目"不发未授权请求"哲学:此命令爬目标公开 HTTP 资源(类似搜索引擎爬虫),但仍建议有授权

---

## [1.3.3] — 2026-05-09

🎯 **子域名枚举阶段反馈** —— 消除"输入域名后卡 5-15 秒不知在做什么"的困惑。

### ✨ Features / UX

- **4 个阶段实时反馈**(写 stderr,仅 TTY,不污染管道):
  - `阶段 1/4:拉取被动数据源(crt.sh / HackerTarget / OTX / ThreatCrowd)...`
  - 每个源完成时即时输出候选数:`[crtsh] 142 个候选` / `[hackertarget] error: rate limit`
  - `阶段 2/4:通配符 DNS 检测 ...` → `无通配符` / `检测到通配符 — 结果可信度降低`
  - `阶段 3/4:DNS 解析 N 个候选 ...`(沿用现有进度条)
  - `阶段 4/4:HTTP probe N 个活跃子域 ...`(沿用现有进度条)
- **`_stage_log()` helper** 仅在 `sys.stderr.isatty()` 时输出,管道场景静默
- **新增 8 个 i18n 键**(中英双语):`subdomain.stage_passive/wildcard/dns/probe` / `source_done/source_err` / `wildcard_yes/wildcard_no`

### 🐛 Bug Fixes

- 之前用户输入域名后看到"黑屏 5-15 秒 → 突然出进度条",体验断层(根因:被动多源拉取阶段 + wildcard 探测阶段无任何反馈)
- `passive_collect_subdomains` 加 `show_progress=True` 参数;调用方默认开启,测试用 `False` 静默

### 🧪 Tests

- **+8 个新测试**(全套 368 → 376):
  - `TestSubdomainStageProgress` × 6:每源逐个出衡 / 静默模式 / error 显示 / 非 TTY 静默 / 4 stage header / show_progress=False
  - `TestSubdomainStageI18n` × 2:i18n 键完整 + 双语本地化
- 修复 4 个旧 mock 签名(添 `**kw` 容纳 `show_progress` 关键字)

### 📦 Packaging

- `__version__` 1.3.2 → 1.3.3

---

## [1.3.2] — 2026-05-09

🛠 **质量打磨 + 电话运营商 MNP 修复 + UX 优化** —— 围绕"用户实际使用"的多面修复。

### 🐛 Bug Fixes

- **📞 电话运营商误导修复(MNP-aware)** —— 用户报告西班牙号 `+34600320351` 显示为 Vodafone,实际是 Jazztel(Orange España 集团)
  - **根因**:phonenumbers 库基于静态号段映射(libphonenumber 内嵌的 ITU/CNMC 公开数据),不感知 MNP 携号转网。 `+34600` 号段 2001 年由 Vodafone 收购 Airtel 时获得,phonenumbers 数据正确反映了号段所属
  - **解决**:**双层防御** — Layer 1 静态号段 + 清晰 disclaimer 标签(总是开启);Layer 2 可选实时 HLR API(env var opt-in)
  - 字段标签:`运营商` → `运营商(号段所属)` / `Carrier` → `Carrier (block-allocated)`
  - 输出附 ↳ 子条:`号段原始分配方;实际运营商可能因携号转网(MNP)与此不同`
  - 新增 4 个 i18n 键(中英):`field.carrier_realtime` / `phone.mnp_note` / `phone.realtime_hint` / `phone.realtime_failed`
  - **可选实时 HLR**:设 `SPYEYES_PHONE_API_KEY=numverify:YOUR_KEY` 自动启用(numverify free tier 100 次/月);失败优雅降级
  - 可扩展 provider 接口 `_PHONE_PROVIDERS` dict,以后可加 numlookupapi / abstractapi / IPQualityScore
- **📄 PDF 报告中文显示成 □ + 字符间距过紧修复**
  - **根因 1**:reportlab 默认 Helvetica/Times 不含 CJK glyph → 中文字符渲染为 □
  - **根因 2**:STSong-Light(中文 CID 字体)Latin advance width 偏窄,英文/数字字符过紧贴
  - **解决**:注册 reportlab 内置 `STSong-Light` CID 字体 + **字体回退**(`_PDF_LATIN_RUN_RE` regex 把连续 ASCII 段切到 Helvetica,Paragraph 内嵌 `<font name="Helvetica">...</font>`)
  - 同时修复:用户输入未 XML escape(URL 含 `&` 可让 reportlab 解析失败)→ `_pdf_para_text` 完整 escape `& < > \r \n`
- **📊 PDF 表格排版乱修复**
  - 长 IP 列表挤一行撑爆单元格 → `_pdf_format_ips` 每个 IP 一行,> 4 个截断显示 `+N more`
  - 长 hostname/CNAME/title 文本溢出 → `Paragraph` 自动换行
  - 列宽超 A4 可用宽度 → 文档 margin 36pt(可用 523pt),列宽统一收到 ≤ 520pt
  - `HTTP` 列名分行成 `HT`/`TP` → 列宽 30 → 45pt
- **🎨 D3.js Graph 节点堆左上角修复(v1.3.0 引入)**
  - `forceCenter(0,0)` 拉到 SVG 坐标 (0,0) 但没设 viewBox 让原点居中 → 节点全在左上角
  - `fitToView` 在 `bbox.width||bbox.height === 0` 时早退 → 永远不 fit
  - 修复:加 `applyCenterViewBox()` viewBox 居中 + `fitToView` 加 fallback + 4 次自动 fit 重试 + 用户拖拽后停止自动 fit

### ✨ Features

- **🔄 交互菜单加全局"返回主菜单"** —— 之前只有 `[ 9 ]` 切换语言能 `[ 0 ]` 返回,其它 7 个子功能输入步骤无法取消
  - 新增 `_ask_input(prompt_key)` 统一 helper:输入空 / `0` / EOF / Ctrl+C 都返回 None → 退回主菜单
  - 主菜单底部加全局 hint:`(在任意子功能中输入 0 或直接回车可返回此菜单)` / `(In any sub-menu, enter 0 or press Enter to return here)`
  - 影响:`[1]` IP / `[3]` Phone / `[4]` Username / `[5]` WHOIS / `[6]` MX / `[7]` Email / `[8]` Subdomain 全部支持

### 🎨 UX/打磨

- **PDF 表格统一视觉**:新 `_pdf_table_style()` helper(浅灰表头 + 网格 + 5pt 单元格 padding + 隔行斑马纹)
- **PDF 行高放宽**:`Normal.leading=12` / `Title.leading=22` / `Heading2.leading=16`,中文字体下不再挤
- **PDF 长表格分页表头重复**:`repeatRows=1`
- **PDF 文档边距**:36pt(默认 72pt)给宽表格更多空间

### 🔒 Security

- PDF Paragraph 内文 XML escape `& < > \r \n` 防 reportlab 解析器误解析用户输入(URL 含 `&` 等)
- numverify provider 调用走 `safe_get`(沿用现有 connection pool + timeout 防御)
- env var malformed 检测(无 `:` / 缺 provider / 缺 key 一律视为未配置,不抛异常)

### 🧪 Tests

- **+18 个新测试**(全套 350 → 368):
  - `TestPhoneCarrierMNP`(8):disclaimer 双语 / env var / 优雅降级 / provider mock / 实时 HLR 集成
  - `TestNumverifyProvider`(7):HTTP 200 / 500 / non-JSON / API error / 空 carrier 优雅处理
  - `TestPhoneI18nKeys`(2):4 个新键中英完整 + 标签 block-aware
- 全套 lint 全清:ruff / mypy / bandit(0 issue)

### 📦 Packaging

- `__version__` 1.3.0 → 1.3.2

---

## [1.3.0] — 2026-05-09

🌐 **新增子域名枚举(被动多源 + DNS 验证 + HTTP probe)** —— 第 8 个核心 OSINT 能力。

### ✨ Features 新功能

- **🔎 `spyeyes subdomain example.com` 子命令** —— 一站式子域名情报:
  - **被动多源汇总**:并发拉取 4 个公开数据源,任一源挂掉不影响整体
    - `crt.sh` —— Certificate Transparency 日志(免费、无 API key、覆盖率高)
    - HackerTarget hostsearch(每日匿名 quota,触发限速时优雅降级)
    - AlienVault OTX passive_dns
    - ThreatCrowd domain report
  - **Wildcard DNS 探测**:用 32 字符随机前缀做 DNS 查询,命中即标 `wildcard_suspect`,
    通配符域(blogspot/github.io 等)结果可信度降级显示
  - **DNS 主动验证**:并发(默认 30 worker)对每条候选跑 A/AAAA/CNAME,确认活性
  - **HTTP probe(默认开,`--no-probe` 关闭)**:对 alive 子域抓 status_code + `<title>`
    (https 失败回退 http;只读 16KB body 早停;复用现有 `_get_session` 连接池)
  - 返回结构含 `domain / sources / wildcard_suspect / subdomains[] / _stats`,
    每条子域 `host / alive / a / aaaa / cname / http_status / title / scheme`
- **🌍 全报告本地化** —— 8 种报告格式都加 subdomain 专用渲染分支:
  - **Markdown / HTML / PDF / TXT** 表格列出 host / IP / CNAME / HTTP / title;
    HTML alive 子域渲染为可点击 anchor
  - **CSV** 7 列 `host, alive, a, aaaa, cname, http_status, title`(injection-safe)
  - **XMind** 按 alive/dead 两支组织树形,alive 节点带 URL hyperlink
  - **D3.js Graph** 域名为中心节点(group=1),alive 子域 group=2(蓝)/dead group=3(灰)
  - 中英双语 16 个新 i18n 键(`subdomain.*` + `menu.subdomain` + `prompt.input_subdomain`)
- **🎯 交互菜单 `[ 8 ]` 子域名枚举** —— 主菜单从 9 项扩到 10 项;
  - `[8]` = 子域名枚举(原)/`[9]` = 切换语言(让位)/`[0]` = 退出
  - 进入后选 `1=Yes(默认)/2=No` 是否抓 HTTP `<title>`
- **🔢 CLI flags**:
  - `--no-probe`:仅 DNS 不抓 HTTP(快/匿名场景)
  - `--workers N`:DNS/probe 并发(默认 30,与系统 resolver 友好;最大 200)
  - `--timeout T`:单 probe 超时(默认 5s)
  - `--alive-only`:终端打印仅显示活跃子域(JSON/报告仍含完整数据)
- **📚 历史记录**:`history` 子命令显示子域名查询的 `alive/total` + ⚠wildcard 标记

### 🔒 Security 安全

- **`_clean_subdomain_candidates` 输入归一化**:
  - 大小写归一化 + 过滤 wildcard `*.` 前缀 + 去 trailing dot
  - **跨域过滤**:被动源串域返回的 `evil.com` 强制丢弃(防数据污染)
  - 字符白名单(`a-z 0-9 . - _`)拒绝空格/斜杠/控制字符
  - hostname 长度上限 253 字符(DNS spec)
  - 拒绝含 `\n` `\r` 的项(crt.sh `name_value` 多行已在上层 split)
- **入口域名校验** 沿用 `_normalize_domain`(IDN/punycode/`_dmarc` 子域支持)
- **wildcard 探测用 `secrets.token_hex(16)`**:32 字符密码学随机前缀,假阳性率 ~0
- **HTTP probe 仅 alive 子域**:不对未解析子域发请求(省时间 + 减目标侧噪声)
- **JSON `</` 转义**(graph 已有;新增 subdomain 节点也走同路径,无 XSS)

### 🧪 Tests 测试

- **+44 个新测试**(全套 306 → 350):
  - `TestSubdomainCleanCandidates`(9 测试):跨域过滤、wildcard 剥离、字符白名单、长度上限、None/非字符串容错
  - `TestSubdomainParsers`(8):4 源 mock(成功/网络失败/限速/非 dict 响应)
  - `TestPassiveCollectSubdomains`(2):多源并发 + 单源失败容错
  - `TestEnumerateSubdomains`(5):无效域名拒绝、完整流程、`probe=False`、wildcard 标记传递、MAX 截断
  - `TestSubdomainProbe`(5):title 提取、Unicode title、4xx 不抓 title、https → http 回退、全失败兜底
  - `TestSubdomainCli`(5):argparse(`--no-probe` / `--alive-only` / `--workers` 校验)+ run_cli json
  - `TestSubdomainReports`(8):8 种格式 × 关键内容验证 + wildcard 警告 + HTML alive anchor
  - `TestSubdomainHistoryRecord`(1):history.jsonl 写入 alive/total
  - `TestSubdomainI18nKeys`(1):16 个新 i18n 键中英完整性
- 全套 lint 全清:ruff / mypy / bandit(0 issue)

### 📦 Packaging 打包

- `__version__` 1.2.0 → 1.3.0
- `pyproject.toml` description 加入 "Subdomain enumeration"

---

## [1.2.0] — 2026-05-02

🎨 **8 种报告格式 + 全报告 i18n + 菜单流程优化** —— 围绕"用户输出"的全方位升级。

### ✨ Features 新功能

- **📊 报告格式从 3 种扩展到 8 种** —— 按文件后缀分发，无新强依赖
  （XMind 纯标准库实现；Graph 用 D3.js v7 from CDN）：

  | 格式 | 后缀 | 实现 | 适用场景 |
  |---|---|---|---|
  | JSON | `.json` | stdlib | 管道处理、脚本 |
  | Markdown | `.md` | 已有 | GitHub Issue / 笔记 |
  | **HTML** 🆕 | `.html` | stdlib + 内嵌 CSS | 浏览器查看、邮件附件 |
  | PDF | `.pdf` | reportlab (extras) | 正式报告 |
  | **TXT** 🆕 | `.txt` | stdlib | 复制粘贴到 ticket |
  | **CSV** 🆕 | `.csv` | csv stdlib + injection 防护 | Excel / Sheets 数据分析 |
  | **XMind** 🆕 | `.xmind` | zipfile + xml stdlib | 思维导图（XMind 8 兼容） |
  | **Graph** 🆕 | `.graph.html` | D3.js v7 (CDN) | 力导向图，可点击跳转 |

- **🌍 报告全本地化** —— 所有 8 种格式的标题 / 列头 / 标签 / 类别名都跟随 UI 语言
  （新增 21 个 `report.*` i18n 键，覆盖中英双语）。例如：
  - `SpyEyes Report` / `SpyEyes 报告`
  - `Username scan` / `用户名扫描`
  - `Profile URL` / `主页地址`
  - 类别名：`Code & Dev` / `代码与开发`
  - Graph legend / help 提示文字也本地化
  - HTML 加 `<html lang="zh|en">` 属性
- **🧬 Maigret-style permute** —— `itertools.permutations` 全排列：
  - 所有子集大小 2..N 的全排列 × 4 种分隔符 `['', '_', '-', '.']`
  - size-2 排列额外生成首字母变形（`jdoe` / `j.doe` / `jd` / `j_d` 等）
  - 新增 `--method strict|all` flag：`all` 在 strict 基础上加 `_前缀` / `后缀_` 变体
  - 现有测试 100% 向后兼容
- **🚀 默认并发 100 → 150** —— `track_username` / `recursive_track_username`
  / CLI `--workers` 默认值统一升级 50%；`_check_username` 单平台超时不变 (5s)
- **🗂 默认报告路径 `~/Downloads`** —— 交互模式智能默认到下载目录
  （macOS / Linux / Windows 标准），fallback `~/Download` → `~/spyeyes-reports/` → cwd
- **🔢 交互式格式选择器** —— 选择"保存"后弹出 1-8 数字菜单
- **🔁 多格式连续保存** —— 保存完一种后追问"还要保存其它格式吗？"循环；时间戳每轮重算，多次保存得到不同文件名

### 🎨 UX 改进

- **菜单从 9 项缩到 8 项**：原 `[8] 用户名变形` 合并到 `[4] 用户名追踪` 子流程：
  - 进入 [4] 后先选策略：`1. 直接扫描` / `2. 变形 + 批量扫描` / `3. 仅生成变形`
  - 选 2/3 时进一步选 `--method strict|all`
  - 语言切换从 `[9]` 移到 `[8]`
- **D3.js Graph 大改**：
  - 修复 354+ 节点时上下被裁剪的问题（`flex` 布局让 SVG 占满视窗剩余空间）
  - 加 `d3.zoom()` 滚轮缩放 + 拖拽空白处平移（scale 0.05–8）
  - 模拟稳定后或按 <kbd>F</kbd> 自动 fit 到完整可见，<kbd>R</kbd> 重置缩放
  - 文字加白色描边 (`paint-order: stroke`)，密集区也清晰
  - 节点越多，charge 越强 + radial force 把命中平台推到外圈
  - 窗口 resize 自动 refit
- CLI `--help` epilog 列出所有 8 种格式示例

### 🔒 Security 安全

- `_html_escape()`：转义 `& < > " '` 防 HTML/XML 注入（用于 HTML / XMind / Graph）
- `_csv_safe()`：单元格首字符为 `= + - @ \t \r` 时前置 `'`，防 Excel/Sheets 公式注入
- `_to_graph_html` 把 JSON 中的 `</` 转义为 `<\/` 防 `</script>` 注入
- 所有用户输入字段在 8 种报告里都做对应的 escape

### 🐛 Bug Fixes 修复（独立审计发现）

- **HTTP pool_maxsize 64 → 200**：v1.2.0 升级到 150 worker 后原 64 的连接池成了瓶颈，
  urllib3 频繁重建连接部分抵消并发提升。现在 pool_connections / pool_maxsize 都是 200。
- **`my_ip` 报告标题错乱**：`prefix.partition('_')` 把 `'my_ip'` 切成 `cmd='my', query='ip'`
  导致 8 种报告里全部显示 "MY 信息: ip"。改 `save_prefix` 为 `'myip'` 一处修复全部。
- **MX 报告在 HTML/TXT/CSV/PDF/XMind 错误回退**：之前只有 Markdown 有 MX 专用渲染分支，
  其它 5 种格式落到通用 dict 把 records list 压成 Python repr。补齐每种格式的 MX 表格分支。
- **permute method='all' 截断丢失核心变体**：`_` ASCII 95 < 字母 97，纯字母序排序让
  `_xxx` 占满前 200，`johndoe` 等核心变体被丢掉。新增 `_permute_sort_key` 把装饰过的
  `_前缀` / `后缀_` 变体排到非装饰变体后面，截断时丢的是装饰版而非核心。
- **permute_scan 报告几乎为空**：交互菜单 `[4]→2`（变形+扫描）的数据形态是
  `{variation: track_result_dict}`，之前 6 种生成器都落到通用 dict 把每个 variation 的
  扫描结果压成单格 `k=v, k=v` 字符串。现在每种格式都有专属 permute_scan 分支：
  - Markdown / HTML / PDF / TXT：每个变形一个子节，列出命中平台
  - CSV：扁平化为 `(variation, category, platform, url)` 四列
  - XMind：每个变形一棵子树
  - Graph：多中心力导向图（每个 variation 一个红心 + 蓝色平台子节点）
- **XMind mimetype 兼容**：按 XMind 8 spec 把 `mimetype` 作为第一个 zip 条目（uncompressed），
  类似 EPUB 格式约定，提升不同 XMind 版本兼容性。

### 🧹 Cleanup 清理

- 删除已无引用的 i18n 键：`menu.permute` / `prompt.permute_input` / `prompt.permute_scan` / `prompt.save_as`
- CHANGELOG `[Unreleased]` 段中的 "XMind 思维导图报告输出" 已实现，从 roadmap 移除
- `.github/release-notes-v1.0.0.md` → `docs/releases/v1.0.0.md`（CHANGELOG 已含完整内容，归档单文件版本）
- `_default_report_dir()` 加模块级缓存，多格式连续保存循环不再重复 stat
- CI 测试矩阵加 Python 3.14（lint job 也升 3.13 → 3.14；Codecov 上传跟随升级）

### 🧪 Tests 测试

- 全套 306 个测试 100% 通过（向后兼容验证）
- 新增 8 种格式 × 2 种语言 × 4 种数据形态的烟囱测试
- 新增 P0-3 / P0-4 / P1-1 / P1-2 修复的回归验证

### 📦 Packaging 打包

- `__version__` 1.1.0 → 1.2.0
- `pyproject.toml` description 更新提及 8 种报告格式 + 加 Python 3.14 classifier
- 主依赖未变（仍是 4 个核心 + 1 个可选 `[pdf]`）

---

## [1.1.0] — 2026-05-02

🚀 **Maigret 融合升级** —— 平台数 +57%，新增三大功能（用户名变形 / 递归扫描 / PDF 报告）。

### ✨ Features 新功能

- **📈 平台库扩容到 3164 个**（从 2067 → 3164，+57%）
  - 关键升级：解析 Maigret 的 **engine 模板系统**（Discourse / XenForo / phpBB / vBulletin），
    1097 个共享配置的论坛站点不再丢失。Maigret 单源贡献从 1422 → 2519。
  - 引入 Maigret 上游 **tags 体系**（cn/jp/ru/photo/dating 等），分类更精确。
  - 论坛类 285 → 733（+157%），代码类 50 → 115（+130%），游戏类 39 → 95。
- **🧬 用户名变形 (`spyeyes permute "John Doe"`)** —— 灵感来自 Maigret `--permute`
  - 自动生成 `johndoe` / `j.doe` / `john.d` / `jdoe` / `jd` 等 22+ 变形
  - 支持空白/逗号/分号/点/下划线/连字符多种分隔符
  - 支持 Unicode（中文姓名 "张 三" 也能生成 10 个变形）
  - 安全限制：最多 4 个输入片段、200 个输出（防 DoS）
  - `--scan` 选项：批量扫描每个变形（找化名常用）
- **🔁 递归扫描 (`spyeyes user X --recursive`)** —— 灵感来自 Maigret recursive search
  - 在命中页面用保守正则提取 `@handle` 与社交平台 URL 中的次级用户名
  - 自动在 visited 集合内去重（防循环），最多 2 层、每层 5 个新候选、每层抓 8 个页面
  - `--depth N` 控制递归深度（0-2）
  - 输出含层级总结：`[depth N] username → M hits`
- **📄 PDF 报告 (`--save report.pdf`)** —— 通过可选 `reportlab` 依赖
  - 安装方式：`pip install "spyeyes[pdf]"`
  - 适用所有子命令（IP/Phone/Username/WHOIS/MX/Email），表格+样式+分类小节
  - 用户输入字段全部 escape，防止 PDF 注入（继承 Markdown 防御）
  - 缺失依赖时友好降级提示，不打印 traceback
- **🌐 双语 i18n 完整支持** —— 9 个新键全部覆盖中英两版

### 🔧 Improvements 改进

- **build_platforms.py 工具升级**
  - `parse_maigret()` 现在解析 `engines` 字段（支持 `{urlMain}{urlSubpath}` 模板替换）
  - 引入 `MAIGRET_TAG_MAP` 把 Maigret tags 映射为 SpyEyes 分类
  - 旧格式回退更稳健：`sites` 顶层键缺失时仍工作
- **CLI epilog 示例更新** —— 新功能均在 `--help` 例子中列出
- **扫描模式标签重新校准** —— Quick 14s/Full 30s（因平台数翻倍）

### 🧪 Tests 测试

- **+42 个新测试**（全套 264 → 306）
- 新增覆盖：permute 边界、Unicode、递归 visited 去重、PDF 安全 escape、CLI 路由
- 多语言一致性：i18n 键完整性自动检查（防止某语言漏键）

### 📦 Packaging 打包

- `pyproject.toml` 新增 optional extras：`spyeyes[pdf]` / `spyeyes[all]`
- 主包仍保持 4 个核心依赖（零膨胀）
- `__version__` 1.0.0 → 1.1.0

---

## [1.0.0] — 2026-04-30

🎉 **SpyEyes 首个稳定版本发布** —— 经过完整代码审计 + 多轮回归验证。

### ✨ Features 核心功能

- **🌐 IP 追踪** — IPv4 / IPv6 全支持，国家/城市/ISP/ASN/经纬度，国家中文名映射（180+ 国家）
- **📡 本机 IP 查询** — 一键显示当前公网出口 IP
- **📱 电话号码追踪** — 中文归属地 + 中文运营商 + 12 种号码类型 + 国际/E.164 格式
- **👤 用户名扫描** — **2067 个平台**（合并 Maigret + Sherlock + WhatsMyName 三大上游）
  - 46 中文圈（陆/台/港/星/马）+ 52 西语圈（西班牙/拉美）+ 83 成人/约会
  - **100 线程并发**，21 秒扫完
  - WAF 检测（Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai 等）
  - regex 预过滤 + ReDoS 长度限制防护（`MAX_USERNAME_LENGTH=64`）
  - HEAD 优化 + 405/501 GET 回退
  - 命中可信度排序（★★★/★★/★）
- **🔍 域名 WHOIS** — 注册商、日期、DNS 服务器、注册组织（含基本格式校验防注入）
- **📨 域名 MX 记录** — 列出所有 MX 优先级
- **✉️ 邮箱有效性验证** — 正则 + MX 联合检查（mx_error 收敛为枚举防信息泄漏）
- **📚 查询历史** — `~/.spyeyes/history.jsonl`（损坏行容错）+ `spyeyes history [--limit N] [--search STR] [--json]` 子命令查询
- **📝 Markdown 报告** — `--save report.md`（含 backtick / pipe / newline 注入转义）

### 🌍 i18n 国际化

- 完整中英双语 UI（~140 翻译键）
- 首次启动语言选择器
- CLI `--lang zh|en` + 菜单 `[8]` 切换
- 偏好持久化到 `~/.spyeyes/config.json`（损坏文件容错）

### 🔒 Security 安全

- **SSRF 防护** — `track_ip` 用 `ipaddress.ip_address()` 校验，拒绝路径穿越（`'../admin'`）和 query string 污染（`'8.8.8.8?key=leak'`）
- **ReDoS 防护** — `MAX_USERNAME_LENGTH = 64` 截断恶意输入，防止 `(a+)+` 类指数回溯
- **Domain 校验** — `whois`/`mx` 入口用 `DOMAIN_RE` 拒绝换行注入 / URL 形式 / 路径片段
- **MX 错误信息收敛** — DNS 内部细节（server IP / 解析器栈）不泄漏到 `--json` 输出，收敛为 `nxdomain` / `no_mx` / `invalid_domain` / `dns_failed` 枚举
- **Markdown 注入防护** — 用户输入字段（username / ip / domain）的 `|`、换行、反引号转义，防 GitHub PR / Obsidian / VSCode preview 渲染攻击
- **WAF 高精度指纹** — 使用各 WAF 自有的特定标志（`cdn-cgi/challenge-platform` 等）而非 `cloudflare` 等泛词，假阳性极低

### ⚡ Performance 性能

- **100 线程并发**扫描 + per-thread `requests.Session`（连接池复用）
- **HEAD 请求**（仅检测 status_code 时）+ 405/501 自动回退 GET
- **stream + 64KB 早停**（避免大页面下载）
- **拆分 timeout** `(connect=3s, read=5s)`
- **PLATFORMS 懒加载**（PEP 562 `__getattr__` + `__dir__` 保持 IDE 兼容）
- 实测：全 2067 平台 21s / `--quick` 9s / `--category code` 3s

### 🛠 Reliability 可靠性

- `safe_get` 拓宽异常列表覆盖 `urllib3.LocationParseError` / `UnicodeError` / `OSError`
- `_check_username` body 循环读取保证拿满 64KB（chunked encoding 短读取防护）
- `_batch_lookup` 支持 `Ctrl+C`（`cancel_futures=True`）
- `_maybe_save` `OSError` 友好提示而非抛 traceback
- `whois_lookup` 处理 python-whois 在罕见 TLD 返回 `None`
- `track_phone` 拒绝 `is_possible_number=False` 的号码（之前会被误记为成功）
- `tools/build_platforms.py` 原子写（`tempfile + os.replace`）+ 重试退避

### 🛠 Developer Experience

- **264 个 pytest 测试**，0.4 秒跑完
  - 主功能测试（220 个）+ 构建工具测试（40 个）
  - 覆盖：纯函数 + HTTP mock + 边界条件 + SSRF / ReDoS / Markdown injection / 信息泄漏 / Platform 不可变性 / 损坏文件容错 / 跨线程隔离
- **5 路审计全清** — ruff / mypy / bandit / pytest / fresh-eyes agent reviews
- **GitHub Actions CI** —
  - Lint job: ruff + mypy + bandit
  - Test matrix: macOS / Ubuntu / **Windows** × Python 3.10-3.13（8 jobs）
  - `--cov=spyeyes` / `--timeout=15` / `--timeout-method=thread` (Windows-safe)
  - `concurrency` 取消同分支重复 build
- **autouse fixture** 隔离 `_lang` / `Color` / thread-local Session / `_PLATFORMS_CACHE`
- **Apache License 2.0**（含明确专利授权 + 商标保护）
- **Dependabot** 自动依赖升级
- **`requirements.txt` 加上限**（`requests<3` 等）防上游 major 破坏 API
- **`requirements-dev.txt`** 分离开发依赖
- **`pyproject.toml`** 支持 `pip install` + `python_requires>=3.10`

### 🎨 UX

- ANSI Shadow 风格 SPYEYES Banner
- 实时进度条（仅 TTY 模式）
- 4 种扫描模式（菜单内选）：快速 / 完整 / 中文+西语 / 仅代码
- 批量域名 MX/WHOIS（`spyeyes mx domain1 domain2 ...`）
- `__version__ = '1.0.0'` + `--version` CLI flag

---

[Unreleased]: https://github.com/Akxan/SpyEyes/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Akxan/SpyEyes/releases/tag/v1.0.0
