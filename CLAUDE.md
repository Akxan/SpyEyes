# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在本仓库中工作时提供指引。

> 约定:与用户对话、git 提交信息、本文件一律使用**中文**(代码标识符 / 命令 / 路径保持原样)。
> 对外页面(GitHub 仓库描述、`README.md`、Pages 首页)**英文为主、中文为辅** —— 见「对外页面」一节。

## 项目概览

SpyEyes 是 Python 3.10+ 的一站式 OSINT 命令行工具(`spyeyes` / `python -m spyeyes`)。
14 个子命令:`ip` · `myip` · `phone` · `user` · `permute` · `whois` · `mx` · `email` ·
`subdomain` · `domain-emails` · `history` · `diff` · `investigate` · `upgrade`。
不带子命令 → 进入交互菜单。中英双语:界面文案、错误信息、**报告内容**都随 `--lang` 切换。
当前版本见 `spyeyes/__init__.py` 的 `__version__`(必须与 `pyproject.toml`、
`docs/CHANGELOG.md`、git tag 保持一致 —— 每次发版提交时一起改)。

## 常用命令

```bash
# 开发安装(仓库不带 .venv,先自己建)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .            # 注册 `spyeyes` 入口(editable 安装也算"源码安装")

# 不安装直接从源码跑
python -m spyeyes <subcommand> ...

# 完整 lint(与 CI `lint` job 一致)
ruff check .
mypy spyeyes tools/build_platforms.py --ignore-missing-imports
bandit -c pyproject.toml -r spyeyes/ tools/ -ll   # -ll = 只报 MEDIUM 及以上;不带 -c 时 pyproject 里的 skips 不生效

# 测试(CI 用 --timeout=15 --timeout-method=thread);全量约 2 秒,全部 mock 无真实网络
pytest tests/ -v
pytest tests/ --cov=spyeyes --cov-report=term-missing
pytest tests/test_spyeyes.py::TestTrackIp -v          # 单个类
pytest tests/ -k "subdomain"                          # 按名字子串过滤

# 从上游(Maigret + Sherlock + WhatsMyName)刷新内置 platforms.json
python tools/build_platforms.py
python tools/build_platforms.py --no-fetch --cache-dir .cache   # 离线复用缓存
```

CI(`.github/workflows/ci.yml`):`lint`(Python 3.14)通过后才跑 `test` 和 `package`。`test` 的矩阵为
Linux × {3.10–3.14}、macOS × {3.10, 3.14}、Windows × {3.10, 3.14};Codecov 只从 Ubuntu × 3.14 上传
(需要仓库密钥 `CODECOV_TOKEN`,没有时上传被拒但不报错)。`package` 用 `python -m build` 打出 wheel,
装进干净的虚拟环境、在检出目录之外运行,确认加载到 2500+ 平台 —— wheel 漏掉 `data/platforms.json` 时
程序不报错、只会悄悄剩下精选的 200 来个平台,`pip install -e .` 测不出来。
第三方 Action 固定到提交 SHA(行尾注释标版本,Dependabot 会更新);工作流权限是 `contents: read`。
提交前把 ruff / mypy / bandit / pytest 用 `&&` 串起来跑,任何一步失败都不要提交。
`requirements-dev.txt` **没有**给 ruff 设上限,所以规则集锁在 `pyproject.toml`
(`[tool.ruff.lint] select = ["E4","E7","E9","F"]`)。不要删这一段 —— 新版 ruff 会扩大
默认规则,CI 会无声变红(ruff 0.16 会多出约 170 条)。

## 架构

### 单文件核心(刻意为之)
几乎所有代码都在 **`spyeyes/__init__.py`**(约 9.7k 行)。不要拆分 —— 项目刻意保持单一导入面
(`import spyeyes as sp` 拿到全部符号)。`spyeyes/__main__.py` 只调用 `main()`。
用 `grep -n "^def <name>"` 或 `# ===` 分节横幅定位;**不要相信文档 / 注释里的行号,会漂移。**
大致顺序:CONFIG / env 加载 → UPDATE CHECK → I18N(`TRANSLATIONS`、`t()`)→ Color →
HTTP(`safe_get`)→ 国家名映射 → 打印工具 → IP / 电话 → 用户名(`Platform`、
精选 `PLATFORMS`、`_check_username`、`track_username`)→ permute → 递归 →
WHOIS/MX/邮箱 → 子域名枚举 → diff → 域名邮箱枚举 → investigate → `print_*`
→ 菜单(`MENU_KEYS`、`handle_choice`、`_maybe_save`)→ 报告生成器
(`_to_markdown/_to_pdf/_to_html/_to_txt/_to_csv/_to_xmind/_to_graph_html`)→
升级 + 报告目录 + `menu_loop` → CLI(`build_parser`、`_run_subdomain_batch`、
`run_cli`、`_record_history`、`main`)。

### 入口流程
- `main()` 先把 stdout/stderr 强制成 UTF-8(Windows cp936 遇到 emoji 会崩),解析参数,
  确定语言(`resolve_language`:`--lang` > `~/.spyeyes/config.json` > 环境变量
  `SPYEYES_LANG`/`LC_ALL`/`LANG`),打印缓存里的更新提示 + 启动后台更新检查(`upgrade`
  子命令跳过),然后分发给 `run_cli(args)` 或 `menu_loop()`。
- `build_parser()` 是参数与双语 `epilog` 的唯一来源。每个子 parser 都用 `parents=[common]`
  (`--json --save --no-color --lang --no-update-check --version`);`common` 用
  `default=argparse.SUPPRESS`,读这些属性要 `getattr(args, 'json', False)`
  (`run_cli` 会把 `json` / `save` 归一化)。
- 退出码:0 成功 · 1 查询失败(顶层 dict 含 `'_error'`,**或**批量 whois/mx/subdomain
  中任一项失败)· 2 用法 / 文件错误。`upgrade` 另有 130(Ctrl-C)。

### 插件式数据源注册表
两个 dict 让新增 OSINT 数据源只需加一行:
- `SUBDOMAIN_SOURCES` → `crtsh`、`certspotter`、`hackertarget`、`otx`、`wayback`、
  `subfinder`(仅当 PATH 里有该二进制)。每个 `_src_*` 返回 `set[str]`,且已经过
  `_clean_subdomain_candidates`(跨域过滤 + 字符白名单)。
- `DOMAIN_EMAIL_SOURCES` → `crtsh`、`whois`、`bing`、`ddg`、`wayback`、`github`。
  每个 `_emails_from_*` 返回经 `_is_email_relevant` 过滤的 `set[str]`。

两者都用 `ThreadPoolExecutor(max_workers=len(...))` 并发,**单源失败一律静默吞掉**
(返回空集 + 记录错误)。不要引入源之间的耦合 —— 约定是"任何一源挂掉,其余照常工作"。
`bandit.skips=["B110","B112"]` 就是为此;不要在这种 OSINT 源模式之外新增裸 `except: pass`。
测试用 `monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, name, fn)` 替换数据源 —— 函数是
通过 dict 查找调用的,对模块函数 `setattr` 不起作用。

### 域名邮箱爬虫
`enumerate_domain_emails` → 被动源 → 可选:发现活跃子域(`enumerate_subdomains(probe=True)`,
只保留有 HTTP 响应的 host)→ 最多 3 个 target 并行爬取 → 可选 `--guess` 模式邮箱 → 可选 SMTP 验证。
`max_pages` 是**总**页数预算,按 target 数均分;每个 target 至少要 `DOMAIN_EMAIL_MIN_PAGES_PER_TARGET`(10)页,
所以目标数上限 = `max_pages // 10`,超出的子域不爬并记入 `_stats.targets_skipped`(不要再给每个目标"保底"页数,
那会让总量超出预算)。robots.txt 只认 `User-agent: *` 分组的 Disallow —— 针对别家爬虫的规则与我们无关;
被 robots 挡下的 URL 数记入 `_stats.robots_skipped`,一页没爬时终端会提示原因。单个 target 内是串行 BFS
(`deque` + `enqueued` 去重集合、500 ms 速率限制、`DOMAIN_EMAIL_TOTAL_TIMEOUT` 兜底)。
任何要请求的地址 —— 页面、链接、robots.txt 里的 sitemap —— 都必须通过 `_url_in_domain`
(基于 `.hostname`:带端口的站内链接放行,`user@evil.com` 这类绕过被拒)。新增爬取路径也要
遵守:robots.txt / sitemap 是目标站可控的输入(爬虫 SSRF)。

### 综合调查(`do_investigate`)
MVP 只支持 domain。阶段 1 并发跑 whois / mx / subdomain / domain-emails(邮箱任务用
`include_subdomains=False`,避免子域枚举跑两遍)。阶段 2 的 pivot 是单向 DAG
(活跃子域 A 记录 → `track_ip`;像真人的邮箱本地部分,用 `_personal_email_score` 打分、
跳过 role 账号 → `track_username`),物理上不可能成环。上限:`max_pivot_ips`、
`max_pivot_emails`、`budget`。预算只能截停 *pivot* —— 阶段 1 的线程无法取消,
总会在各自超时内跑完。`graph`(nodes/edges)由 `_build_investigate_graph` 生成,
`_to_graph_html` 负责渲染。

### 报告生成(`--save`)
`_maybe_save(target, prefix, data)` 按文件后缀分发:
- `.json`(默认 / 无后缀)/ `.md` / `.html` / `.pdf`(需 `spyeyes[pdf]`)/ `.txt` /
  `.csv`(以 `utf-8-sig` 写入 —— 靠 BOM 让 Excel 正确显示中文;曾被误回退过一次,有回归
  测试守护)/ `.xmind` / `.graph.html`。
- `.graph.html` 必须在 `.html` **之前**判断。新增格式时保持这个顺序。
- 目录形式的 target(以 `/` 或 `os.sep` 结尾,或已存在的目录)一律写 JSON,文件名
  `<prefix>_<timestamp>.json`。
- `prefix` 形如 `<cmd>_<query>`;生成器按 `prefix.partition('_')[0]` **加上**数据形态判断
  分支(如 `cmd == 'mx' and 'records' in data`、`_is_permute_scan`)。都不匹配的落到通用
  dict 分支,它用 `_flatten_value`(能展开嵌套 dict/list)—— 复用它,别再自己写一份值展平。
- 转义:HTML / Graph / XMind 用 `_html_escape` —— **只在最外层转义一次**(把原始值传给 `t()`,
  再转义结果);CSV 单元格用 `_csv_safe`(防公式注入);Markdown 用 `_md_escape`;
  PDF 用 `_pdf_para`(表格单元格,传原始文本)/ `_pdf_story`(带内联标签的模板,拼进去的用户文本
  必须先过 `_pdf_esc` —— 否则文本里的 `<` 会被当成标签,整份 PDF 生成失败)。
- 用户名结果:`_username_json_view` 是唯一的公开 JSON 视图(剥 `_statuses`,保留
  `_recursive`),`--json` 与 `--save x.json` 共用。
- 所有生成器都遵循 `get_lang()`(标题、标签、CSV 表头)。

### i18n
`TRANSLATIONS = {'en': {...}, 'zh': {...}}`。所有用户可见字符串 —— 终端输出、stderr 警告、
报告文字 —— 都用 `t('some.key', name=value)`。绝不硬编码中文或英文;绝不用字符串拼接
构造消息。新字符串必须同时有 `'en'` 和 `'zh'` 条目 —— 否则
`TestUpgradeI18n::test_en_zh_key_sets_match` 会失败。不再使用的 key 要删掉。
注意模块导入时默认 `_lang = 'zh'`,测试默认是中文,除非显式 `gt.set_lang('en')`。

### 更新检查与一键升级
- 启动:`get_cached_update_info()` 读 `~/.spyeyes/.update_check.json`(24 h 有效,原子写);
  `_start_background_update_check()` 在 daemon 线程里刷新。提示走 **stderr**(绝不污染
  `--json`)。可用 `SPYEYES_NO_UPDATE_CHECK=1` / `--no-update-check` 关闭。交互模式 + TTY 时,
  菜单启动的 Y/N 提示代替这条通知。
- `run_upgrade()` 强制刷新(绕过环境变量开关 —— 这是用户的明确意图),再按
  `_detect_install_mode()`:`packaged-pip` → `pip install --upgrade git+…@<tag>`
  (tag 先经 `_RELEASE_TAG_RE` 校验)、`packaged-pipx` → `pipx upgrade spyeyes`、
  `source` → 只打印 `git pull` 提示。升级成功时它自己 `sys.exit(0)`(当前进程还持有旧模块)。
  调用方必须处理它**正常返回**(=什么都没升级)的情况。
- pip 模式还要看环境:PEP 668「外部管理环境」(Homebrew / 系统 Python,`_is_externally_managed`)
  下 pip 拒绝安装,必须带 `--break-system-packages` —— 这是高风险动作,只能在用户显式同意后加
  (CLI `--break-system-packages`,或 TTY 下单独的 `[y/N]`,默认否;`--yes` 不等于同意);
  装在用户目录(`_is_user_site_install`)时追加 `--user`。conftest 默认把宿主视为非 PEP 668 环境。
- `run_upgrade` 与菜单代码调用的是别名 `_get_cached_update_info`,方便测试 monkeypatch。

### 状态与配置
- `~/.spyeyes/config.json` —— 持久化的界面语言
- `~/.spyeyes/history.jsonl` —— 只记每次查询的元数据(`_record_history`);
  `SPYEYES_NO_HISTORY=1` 关闭
- `~/.spyeyes/.update_check.json` —— 更新检查缓存
- `~/.spyeyes/env` —— KEY=VALUE 格式,由 `_load_env_file()` 在**导入时**自动加载;
  shell 里 export 的值优先。识别的 key:`SPYEYES_OTX_API_KEY`、`SPYEYES_CERTSPOTTER_API_KEY`、
  `PDCP_API_KEY`(subfinder 读取)、`SPYEYES_GITHUB_TOKEN`、`SPYEYES_PHONE_API_KEY`
  (`numverify:KEY`)、`SPYEYES_DNS_WORDLIST`、`SPYEYES_BRUTEFORCE`、`SPYEYES_REPORTS_DIR`、
  `SPYEYES_NO_HISTORY`、`SPYEYES_NO_UPDATE_CHECK`、`SPYEYES_LANG`、`SPYEYES_THEME`。同时遵守 `NO_COLOR`。
- 交互模式默认报告目录(`_default_report_dir`):`SPYEYES_REPORTS_DIR` > 源码安装
  `<仓库>/Downloads/` > 打包安装 `~/Downloads/spyeyes/`(绝不写进 site-packages)。
- 旧版 `~/.ghosttrack/` 首次运行时自动迁移(`_migrate_legacy_config`)。

### 平台数据
2963 个用户名平台 = 精选 `PLATFORMS` 列表(去重后 209 个,含全部中文 / 西语 / 18+ 手选)
**运行时合并** `spyeyes/data/platforms.json`(2852 个,来自 Maigret/Sherlock/WhatsMyName;
重名或同地址时精选优先)。去重同时按名字和地址模板(`_platform_url_key`:忽略 http/https、`www.`、
结尾的 `/`、大小写)—— 上游三个库会给同一个网址起不同的名字,只按名字去重会让同一个账号在结果里出现两次。
- `PLATFORMS` 定义后即被删除;`spyeyes.PLATFORMS` 走 PEP 562 `__getattr__` →
  `_get_platforms()`(懒加载,缓存在 `_PLATFORMS_CACHE`)。测试需要自定义列表时 patch
  `_PLATFORMS_CACHE`,而不是 `PLATFORMS`。
- `_load_platforms_json` 是防御式的:坏条目跳过、空模式剔除(空 bytes 模式会匹配任何页面)、
  不在 `CATEGORY_ORDER` 里的类别归入 `'other'`。
- WhatsMyName 的字段别按首字母猜:`e_string` = 账号**存在**时出现的字符串(→ `must_contain`),
  `m_string` = **不存在**时出现的(→ `not_found`)。v1.1.0–v1.8.6 接反过,587 个平台因此查不到真实账号;
  `TestWmnRulesNotInverted` 守护发布的数据。
- Maigret 的论坛引擎模板:检测规则在 `engine.site.absenceStrs / presenseStrs`,与站点自己的规则合并。
  `engine.presenseStrs`(顶层)是"识别论坛软件"的指纹(`XenForo`、`content="Discourse"`),每个页面都有,
  **不是**检测规则。v1.1.0–v1.8.7 把指纹当成了 must_contain 并漏掉 `engine.site`,1110 个论坛条目因此失效。
- `tools/build_platforms.py` 负责重建 JSON。重名取舍:检测模式更多者胜,平手时
  `maigret > whatsmyname > sherlock`。wheel 通过 `[tool.setuptools.package-data]` 打包该 JSON。
  它会跳过 `protocol` 为 dns / tor / i2p 的条目,丢弃非 http(s) 或带未展开占位符的地址;任一上游的解析结果
  低于 `MIN_PLATFORMS_PER_SOURCE`、或合并后少于 `MIN_PLATFORMS_TOTAL` 时直接失败,不写文件。
  每类规则上限 `MAX_PATTERNS_PER_PLATFORM = 8`(引擎的"用户不存在"提示按语言列,3 条不够)。
- **改内置数据前先对照上游**:`platforms.json` 是 2026-05-02 生成的快照。修数据时取回当时的上游版本
  (GitHub API `commits?path=…&until=…`)逐条核对,只改能精确对上的条目;改完再用修好的脚本对快照
  在内存里重建一遍做比对,并抽样用真实网站验证(一个乱码名 + 一个常见名,看误报和命中的变化)。
  不要凭印象判断上游字段的含义 —— 两次大错都是这么来的。
- 扫描模式菜单和 `--quick` 帮助里写着各类平台数量(`mode.*`),`TestShippedPlatformData` 会拿它们和数据比对;
  README / 教程里的"45 中文圈 + 33 西语圈 + 704 论坛"、类别表、总数 2963(README、教程、`docs/index.md`、
  `docs/_config.yml`、`pyproject.toml`、模块文档字符串)要手动同步;仓库描述和社交预览图用的是约数"2,900+"。
- 路径用 `os.path.realpath(__file__)`,**不要**用 `abspath` —— `abspath` 在 brew/pipx 软链
  安装下会找不到 data 目录,静默丢掉整份 JSON。不要改。

### 用户名判定(`_check_username` / `_check_username_verified`)
- 非 200 不等于「未找到」:429 / 999 直接算被拦(`STATUS_WAF`);403 / 503 要有证据才算 ——
  响应头(`cf-mitigated`、`x-amzn-waf-action`)或响应体里的 WAF 指纹;HEAD 遇到 403 / 503 会换 GET 再看一次。
- **命中复查**:`track_username` 默认(`verify_hits=True`)对每个命中再用乱码用户名
  (`_make_control_username()`)查一次,乱码也命中 → `STATUS_UNVERIFIABLE`,不计入命中。
  这是对付「只看 HTTP 200」平台误报的办法 —— 实测借用上游内容规则反而大幅增加漏判,不要再走那条路。

### HTTP 工具
- `_get_session()` 返回线程本地的 `requests.Session`(连接池 200,150 线程用户名扫描时复用连接)。
- `safe_get(url, timeout=, connect_timeout=)` 返回 `Response | None`,永不抛异常。新的外呼一律
  用它。`connect_timeout` 默认 `min(3, timeout)`;慢的 OSINT 源传 `connect_timeout=10.0` +
  `SUBDOMAIN_SOURCE_TIMEOUT=45.0`(crt.sh 冷启动 TLS 握手很慢)。
- 判断响应用 `resp is None` / `resp is not None`,**绝不能** `if resp:` ——
  `requests.Response.__bool__` 等于 `resp.ok`,4xx/5xx 响应是 falsy。

## 测试约定

- `tests/conftest.py` 的 autouse fixture `reset_global_state`:
  - 把 `CONFIG_DIR` / `CONFIG_FILE` / `HISTORY_FILE` / `UPDATE_CACHE_FILE` / `ENV_FILE`
    重定向到 `tmp_path` —— 新增任何用户数据路径都要加到这里;
  - 清掉会改变行为的环境变量(`SPYEYES_NO_HISTORY`、`SPYEYES_BRUTEFORCE`、
    `SPYEYES_DNS_WORDLIST`、各 API key、`NO_COLOR` …),因为开发者真实的 `~/.spyeyes/env`
    会在导入时注入 `os.environ` —— 新增环境变量开关也要加进这个列表;
  - 设置 `SPYEYES_NO_UPDATE_CHECK=1`,并强制 subfinder 视为"未安装";
  - 重置 `_lang`、`Color.*`、线程本地 session、`_PLATFORMS_CACHE`。新增模块级可变状态
    也要在这里重置。
- `tests/conftest.py` 的 autouse fixture `block_real_network` 从 socket 层拦截连接和 DNS 查询:
  测试里发起真实网络访问会在结束时判失败(即使被测代码把网络错误吞掉了)。新增数据源时记得在相关测试里替换它。
  `reset_global_state` 还会在每个测试后整体还原 `os.environ`(`_load_env_file()` 直接写环境变量)。
- 写完测试做一次变异检查:把被测的那行代码改坏,确认测试会失败。断言要针对具体的值;
  只断言"没抛异常"、`<=` 上限、或条件里带 `or` 的断言,很容易变成改了代码也照过的空转测试。
- 测试 mock `safe_get` / `requests` / `dns.resolver` / `whois.whois` / `subprocess.run` ——
  不要引入真实网络调用。`MagicMock()` 响应永远为真值,会掩盖上面的 `if resp:` bug;
  需要验证状态码语义时用真实的 `requests.Response()`。
- 要测 `track_username` 的命中:mock 的 `safe_get` 若对所有地址都回 200,命中会被复查判成
  `unverifiable`。让乱码名(patch `_make_control_username`)那次请求返回 404,或传 `verify_hits=False`。
- CI 强制每个测试 `--timeout=15`(thread 方式)。遍历全部平台的循环必须很便宜
  (mock 掉 `safe_get`)或限定类别。
- 修 bug 必须附回归测试,且该测试在旧代码上会失败。

## 风格与护栏

- Ruff `line-length = 120`,target `py310`;mypy `--ignore-missing-imports`。
- 可选依赖用 `try: import … except ImportError: HAS_X = False` 模式(`HAS_DNS`、`HAS_WHOIS`)。
  依赖它们的函数先检查标志,缺失时返回 `{'_error': t('err.no_xxx')}`。
- 启动耗时(`import spyeyes` ≈ 95 ms)要守住:重型模块只在用到时导入 —— phonenumbers 的
  `geocoder`/`carrier`/`timezone` 在 `track_phone` 内部导入;reportlab 只用 `find_spec` 探测出
  `HAS_REPORTLAB`,第一次出 PDF 时由 `_import_reportlab()` 填充模块级 `_rl_*` 符号。
  `TestLazyHeavyImports` 用子进程守护;新增重型依赖照此处理,别放回模块顶层。
  `tests/conftest.py` 在收集阶段预热这些模块 —— 冷缓存 CI 上首次导入 geodata 可能 >15 s,
  否则会被 per-test timeout 误杀(PR #13 踩过);新增延迟导入的模块也要加进预热。
- 结果 dict 里 `_*` 开头的 key(`_error`、`_statuses`、`_stats`、`_recursive`、`_filtered`)
  视为私有。JSON 输出只对 `username_*` 结果剥离它们 —— **`mx`/`whois` 批量结果不剥**,
  因为它们的 key 是用户输入的域名,可能合法地以 `_` 开头(`_dmarc.example.com`)。保持这个不对称。
- 用户名输入走 `_is_invalid_username`(64 字符长度上限就是 ReDoS 防线 —— 不要再引入基于模式的
  ReDoS 检测;同时拒绝 URL 元字符、`<>"`、控制字符和行分隔符、`.`/`..`)。域名走
  `_normalize_domain`(拒绝 URL / 路径 / 控制字符,IDN → punycode,允许 `_dmarc` 类 label)。
  新的输入一律复用这两个函数。
- 进度输出写 stderr,且只在它是 TTY 时输出(`_stage_log`、`_print_scan_progress`),
  保证管道 / `--json` 干净。
- 终端配色走 `Color` 的语义角色(`_THEMES` 定义):`Wh` 结构(加粗)、`Gr` 正文(终端本色)、
  `Cy` 标题、`Bl` 次要提示(弱化)、`Ye` 警告、`Re` 错误、`Mage` 点缀、`Brand` Logo。
  默认主题不许用加粗高亮色和黑色,每个代码以 `\033[0` 开头先复位;`SPYEYES_THEME=classic`
  保留旧版亮绿。新增输出时按角色选属性,不要直接写 ANSI 码。

## 新增子命令时

1. 核心函数 `do_xxx(input)` 返回 `dict`(失败带 `_error`,成功返回结构化数据)。
2. 写 `print_xxx(data)` 负责终端输出。
3. 在 `_to_markdown` / `_to_html` / `_to_pdf` / `_to_txt` / `_to_csv` / `_to_xmind` /
   `_to_graph_html` 加报告分支(或依赖通用 `_flatten_value` 分支),并在 `_XMIND_CMD_EMOJI` 加图标。
4. 在 `build_parser()` 加 parser(`parents=[common]`)和 `epilog` 示例,在 `run_cli()` 加分发;
   给 `_record_history` 加分支(未知命令不会写历史)。
5. 菜单:`MENU_KEYS` + `handle_choice` + 对应翻译 key。
6. 每个可见字符串都要有 `t()` key —— `'zh'` 和 `'en'` 都要。
7. 测试:正常路径 + 至少一条 mock 失败路径。
8. 文档:README.md(英文)/ README.zh-CN.md(中文)/ docs/TUTORIAL.md;命令表还出现在 docs/index.md。

## 发版流程

以下几处必须同步修改,否则 CI / 用户看到的版本不一致:
- `spyeyes/__init__.py` 的 `__version__`
- `pyproject.toml` 的 `[project] version`
- `docs/CHANGELOG.md`(Keep-a-Changelog 格式;把 `[Unreleased]` 的条目移进带日期的版本段;
  提交信息用中文 + conventional 前缀,如 `feat(vX.Y.Z): …`、`fix(vX.Y.Z): …`)
- README.md / README.zh-CN.md 的版本与测试数徽章(`docs/index.md`、`docs/_config.yml`、仓库描述里不写版本号和测试数)
  (README 的「项目亮点」按功能组织,不要再按版本追加「🆕 vX.Y.Z」条目 —— 版本变化只写 CHANGELOG)
- git tag `vX.Y.Z` + GitHub Release(更新检查读的是 `releases/latest`,`spyeyes upgrade`
  安装的就是这个 tag)

## 对外页面(GitHub 仓库页 / Pages)

对外页面英文为主、中文为辅,要便于 GitHub 搜索、搜索引擎和 AI 检索找到并准确引用:
- **仓库描述与 topics**(`gh repo edit`):描述以英文一句话说清"是什么 + 能做什么",末尾带一句中文;
  不写版本号、测试数这类会过期的数字(曾经停在 v1.6.12 半年没人发现)。topics 上限 20 个,
  大类词(`osint`、`reconnaissance`、`pentesting` …)与功能词(`username-search`、
  `subdomain-enumeration` …)搭配;换 topic 前先用
  `gh api "search/repositories?q=topic:<名字>&per_page=1" -q .total_count` 看有没有人用。
- **`README.md`**:开头的「What is SpyEyes?」是一句能被单独引用的定义 + 功能清单 + 事实表;
  「FAQ」的小标题直接写成用户会问的问题。新增或删减功能时这两处要同步,说法必须与代码一致。
- **`docs/index.md`**:Pages 首页(落地页),含首屏、功能卡片、命令表、FAQ 和 JSON-LD
  (`SoftwareApplication` + `FAQPage`);FAQ 的问答要与 README 和 JSON-LD 三处保持一致。
  站点用自己的版式 `docs/_layouts/default.html` + `docs/assets/css/site.css`(不用官方主题,不加载外部资源),
  教程 / 更新日志等文档页共用它。`docs/_config.yml` 的 title / tagline / description 会进 `<title>` 和 meta。
  Pages 不渲染 `CONTRIBUTING.md` / `README.md` 这类文件名,除非文件自带 front matter。
  本机没有 Jekyll,改完推送后用浏览器看线上效果;平台数量等数字也写在这页和 `social-card.svg` 里。
- 中文内容放 `README.zh-CN.md`,两份 README 的章节要对等(曾经中文版缺环境变量表、退出码、安全入口)。
- 站点的社交预览图是 `docs/assets/social-card.jpg`(源文件 `social-card.svg`,用 `qlmanage -t -s 1200`
  渲染后 `sips -c 630 1200` 裁切)。GitHub 仓库页自己的预览图只能在 Settings 里手动上传,API 改不了。

文档入口:`README.md`(英文,主入口)/ `README.zh-CN.md`(中文)/ `docs/TUTORIAL.md`(中文)/
`docs/CHANGELOG.md` / `docs/CONTRIBUTING.md` / `docs/SECURITY.md`;设计文档在 `docs/design/`。
