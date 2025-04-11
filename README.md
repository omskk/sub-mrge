# 订阅合并服务部署指南

## Vercel 部署步骤

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-repo/sub-merge)
1. 点击上方部署按钮
2. 授权Vercel访问您的GitHub账户
3. 选择项目名称和部署区域
4. 在环境变量配置页面设置以下参数（见下文）
5. 点击部署按钮完成部署

## 环境变量配置

| 变量名 | 必填 | 说明 | 示例值 |
|--------|------|------|--------|
| token | 是 | 订阅访问令牌 | xxxxxxxxxxxxxxxxxxxxxx|
| subname | 否 | 订阅显示名称 | 私人订阅 |
| subupdatetime | 否 | 订阅更新时间(小时) | 6 |
| subscriptions | 是 | 订阅源配置 | Sanfen,http://example.com/subscribe |
| nodes | 否 | 自建节点配置 | vless://user@example.com |

## 订阅使用方法

部署完成后，访问以下URL获取订阅：

```
https://your-project-name.vercel.app/your-token
```

其中`your-token`需替换为您设置的`token`环境变量值。

## 注意事项

1. 建议定期更新`token`以保证安全性
2. 订阅源配置格式为：`订阅名称,订阅URL`，每行一个订阅
3. 自建节点支持vless/vmess/trojan/ss等协议