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
