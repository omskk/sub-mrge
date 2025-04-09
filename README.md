# 🚀 订阅合并工具 - Cloudflare Pages 部署指南

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)
![Cloudflare](https://img.shields.io/badge/Cloudflare-Pages-orange)

---

## 📌 项目概述

这是一个基于Flask的订阅合并工具，可以将多个Clash订阅源合并为一个统一的订阅配置，并支持自建节点配置。

### ✨ 主要特性

- 多订阅源合并
- 自建节点支持
- 自动更新机制
- Cloudflare Pages一键部署
- 自定义域名支持

## 🛠 部署到Cloudflare Pages

1. Fork项目推送到自己的GitHub仓库
2. 登录Cloudflare控制台，进入Pages服务
3. 点击"创建项目"，选择"连接到Git"
4. 选择您的GitHub仓库
5. 在构建设置中：
   ```
   构建命令: pip install -r requirements.txt
   构建输出目录: /
   Python版本: 选择3.8或更高
   ```
6. 点击"保存并部署"

> 💡 提示: 确保您的GitHub仓库是公开的，否则需要配置访问权限。

## ⚙️ 环境变量配置

在Cloudflare Pages的"设置"→"环境变量"中配置以下变量：

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `token` | 订阅访问令牌 | mysecret123 |
| `subname` | 订阅名称 | 我的订阅 |
| `subupdatetime` | 订阅更新时间(小时) | 6 |
| `subscriptions` | 订阅源配置(格式: 名称,订阅地址) | 香港节点,https://example.com/hk.yaml |
| `nodes` | 自建节点配置(可选) | 自建节点1,vmess://... |

## 🌐 自定义域名

1. 在Cloudflare DNS中添加您的域名记录
2. 在Pages项目的"自定义域"中添加您的域名
3. 按照提示完成DNS验证

> 🔗 域名验证通常需要几分钟时间，请耐心等待

## 自动构建

- 每次推送到GitHub仓库的主分支都会触发自动构建
- 可以通过Cloudflare Pages控制台手动触发重新构建

## 🔗 访问订阅

部署完成后，您的订阅地址为：
```
https://<您的域名>/<token>
```

或者使用Cloudflare提供的默认域名：
```
https://<项目名称>.pages.dev/<token>
```

---

