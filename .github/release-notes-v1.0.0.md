# 🎉 SpyEyes v1.0.0 — 首发

**SpyEyes 首个独立正式版本**。一站式 OSINT 工具集，专为中文用户优化。

## ✨ 7 大功能

```bash
spy ip 8.8.8.8           # IP 追踪（含中文国名）
spy myip                  # 本机出口 IP
spy phone +8613800138000  # 电话归属/运营商/时区
spy user akxan            # 2067 平台用户名扫描
spy whois example.com     # 域名 WHOIS
spy mx gmail.com          # 域名 MX 记录
spy email a@b.com         # 邮箱有效性
```

## 🌟 核心亮点

| 维度 | 数据 |
|---|---|
| **平台数** | **2067** （含 46 中文圈 + 52 西语圈 + 84 成人/约会）|
| **扫描速度** | 全平台 21s · `--quick` 9s · `--category code` 3s |
| **UI 语言** | 中英双语（菜单 + CLI + 错误信息）|
| **测试** | **99 个 pytest 单元测试** |
| **WAF 检测** | Cloudflare / AWS WAF / PerimeterX / DataDome |
| **优化** | Session 池 · HEAD · stream · regex 预过滤 · ReDoS 防护 |

## 📦 安装

```bash
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 spyeyes.py
```

## 📚 文档

- [README (中文)](https://github.com/Akxan/SpyEyes/blob/main/README.md)
- [README (English)](https://github.com/Akxan/SpyEyes/blob/main/README.en.md)
- [详细教程](https://github.com/Akxan/SpyEyes/blob/main/docs/TUTORIAL.md)

---

⭐ 觉得好用就给个 Star，谢谢！
