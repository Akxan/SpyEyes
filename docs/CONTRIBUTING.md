# 贡献指南

感谢你考虑为 GhostTrack-CN 做贡献！

## 开发环境

```bash
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov
```

## 运行测试

```bash
# 全部测试
pytest tests/ -v

# 带覆盖率
pytest tests/ --cov=. --cov-report=term-missing
```

## 提交流程

1. **Fork** 本仓库到你的账号
2. **建分支**：`git checkout -b feature/my-awesome-feature`
3. **写代码 + 写测试**（新功能必须有对应单元测试）
4. **本地跑通**：`pytest tests/ -v` 全绿
5. **提交**：commit message 中文/英文皆可，建议遵循 [Conventional Commits](https://www.conventionalcommits.org/)
   - `feat: 新增 SOCKS5 代理支持`
   - `fix: 修复 IPv6 解析时的边界情况`
   - `docs: 完善 WHOIS 章节`
   - `test: 增加 email_validate 的边界测试`
6. **推送 + 开 PR**：在 PR 描述里说明改动动机和测试方式

## 代码规范

- **Python 风格**：遵循 PEP 8，函数 / 变量名用 `snake_case`
- **类型提示**：所有公开函数必须有 type hints
- **注释**：只在「为什么这样做」非显而易见时写，不要写「做了什么」
- **中文输出**：所有面向用户的字符串都用中文，错误信息以「：」分隔
- **不引入重依赖**：新功能尽量用标准库，确实需要的第三方库提交时说明理由

## Bug 反馈

请在 [Issues](https://github.com/Akxan/GhostTrack-CN/issues) 提交，包含：

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
