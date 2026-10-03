# 贡献指南

感谢你考虑为 SpyEyes 做贡献！

## 开发环境

```bash
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # 运行依赖 + pytest / pytest-cov / pytest-timeout / ruff / mypy / bandit
pip install -e .                      # editable 安装，注册 `spyeyes` 命令
```

架构约定（单文件核心 `spyeyes/__init__.py`、数据源注册表、报告分发顺序、i18n、测试 fixture 等）请先读仓库根目录的 [CLAUDE.md](../CLAUDE.md)。

## 运行测试

```bash
# 全部测试
pytest tests/ -v

# 带覆盖率
pytest tests/ --cov=spyeyes --cov-report=term-missing

# 单个类 / 单个测试 / 按名字过滤
pytest tests/test_spyeyes.py::TestTrackIp -v
pytest tests/ -k "subdomain"
```

测试**不允许发真实网络请求**——用 `unittest.mock.patch` mock `requests` / `dns.resolver` / `whois.whois`。CI 对每个测试有 15 秒超时（`--timeout=15 --timeout-method=thread`）。

## Lint（与 CI lint job 一致，必须全绿）

```bash
ruff check .
mypy spyeyes tools/build_platforms.py --ignore-missing-imports
bandit -r spyeyes/ tools/ -ll
```

CI：lint job（ruff + mypy + bandit）通过后，才跑 Linux × Python 3.10–3.14、macOS / Windows × Python 3.10 与 3.14 的测试矩阵。

## 提交流程

1. **Fork** 本仓库到你的账号
2. **建分支**：`git checkout -b feature/my-awesome-feature`
3. **写代码 + 写测试**（新功能必须有对应单元测试）
4. **本地跑通**：`pytest tests/ -v` 全绿 + 上面 3 个 lint 命令 0 报错
5. **提交**：commit message 中文/英文皆可，建议遵循 [Conventional Commits](https://www.conventionalcommits.org/)
   - `feat: 新增 SOCKS5 代理支持`
   - `fix: 修复 IPv6 解析时的边界情况`
   - `docs: 完善 WHOIS 章节`
   - `test: 增加 email_validate 的边界测试`
6. **推送 + 开 PR**：在 PR 描述里说明改动动机和测试方式

## 代码规范

- **Python 风格**：遵循 PEP 8，函数 / 变量名用 `snake_case`；ruff `line-length = 120`，目标 `py310`
- **类型提示**：所有公开函数必须有 type hints
- **注释**：只在「为什么这样做」非显而易见时写，不要写「做了什么」
- **中英双语**：项目是双语的——所有面向用户的字符串（界面、错误信息、报告内容）都必须走 `t('some.key', name=value)`，并在 `TRANSLATIONS['zh']` **和** `TRANSLATIONS['en']` 里各加一条；不要硬编码中文或英文，也不要用字符串拼接错误信息。测试里有 en/zh key 一致性检查，漏一边会直接失败
- **不引入重依赖**：新功能尽量用标准库，确实需要的第三方库提交时说明理由；可选依赖用 `try: import … except ImportError: HAS_X = False` 模式
- **新增子命令**：按 [CLAUDE.md](../CLAUDE.md) 的「When adding a new subcommand」清单走（`do_xxx` / `print_xxx` / 报告 / parser / 菜单 / 翻译 / 测试）

## Bug 反馈

请在 [Issues](https://github.com/Akxan/SpyEyes/issues) 提交，包含：

1. **复现步骤**：完整命令和输入
2. **预期 vs 实际**
3. **环境信息**：`python3 --version`、操作系统、依赖版本（`pip freeze`）
4. **报错栈**（如果有）

## 新功能建议

欢迎在 Issues 提 RFC 讨论，或直接发 PR。建议先开 Issue 沟通设计，避免 PR 被拒。

## 行为准则

- 中文 / 英文交流均可
- 对事不对人
- 遵守开源精神：耐心、专业、尊重

---

再次感谢！🙏
