# 🎉 GhostTrack-CN v1.0.0 — 首个正式版

基于 [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack) 全面重构与中文增强。

## ✨ 亮点

- 🌐 **7 个查询功能**：IP / 本机 IP / 电话 / 用户名 / WHOIS / MX / 邮箱
- 🇨🇳 **全中文 UI**：菜单、字段、错误信息、电话归属地、运营商
- ⚡ **用户名扫描提速 10-20×**：10 线程并发，30-60s → 2-3s
- 🎯 **CLI 参数模式 + JSON 输出 + 结果保存**：脚本友好
- 🌍 **180+ 国家中文映射**：IP 显示「美国 (United States)」
- 🧪 **47 个 pytest 测试** + GitHub Actions CI（macOS/Ubuntu × Python 3.9-3.12）
- 📜 **MIT License** 与上游兼容

## 📦 快速开始

```bash
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 GhostTR.py
```

或一行 CLI：

```bash
python3 GhostTR.py ip 8.8.8.8 --json | jq -r '.country'
```

## 📚 文档

- [README (中文)](https://github.com/Akxan/GhostTrack-CN/blob/main/README.md)
- [README (English)](https://github.com/Akxan/GhostTrack-CN/blob/main/README.en.md)
- [详细教程](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/TUTORIAL.md)
- [完整更新日志](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/CHANGELOG.md)

## 🙏 致谢

感谢原作者 [@HunxByts](https://github.com/HunxByts)，以及所有开源 OSINT 社区贡献者。

---

**如果这个工具对你有帮助，请点个 ⭐ Star 支持开发！**
