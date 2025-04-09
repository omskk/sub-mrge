import os
import re
import json
import random
import base64
import uuid
from urllib.parse import urlparse, parse_qs, unquote,quote
from datetime import datetime
from flask import Flask, request, Response

app = Flask(__name__)

# 配置变量
token = 'token'  # 订阅token
subname = '科学订阅'  # 订阅名称
subupdatetime = 6  # 自定义订阅更新时间，单位小时

# subscriptions 配置说明:
# 格式: 订阅组名称,订阅地址,节点命名前缀
# - 订阅组名称: 普通组直接写名称,自动测延迟组加[]
# - 订阅地址: 订阅源地址
# - 节点命名前缀: 可选,默认使用订阅组名称+'-'
subscriptions = """
    名称,http://订阅链接.xxx.com/
"""

# 自建节点配置
nodes = ""

def parse_subscriptions(text):
    """解析订阅配置文本为字典格式"""
    subscriptions = {}
    
    # 清理并分割每行配置
    lines = [line.strip() for line in text.strip().split('\n') if line.strip()]
    
    for line in lines:
        parts = [part.strip().replace(' ', '') for part in line.split(',')]
        name = parts[0]
        url = parts[1]
        prefix = parts[2] if len(parts) > 2 else None
        
        # 检查是否是自动测延迟组
        is_url_test = re.match(r'^\$\$(.*)\$\$$', name)
        if is_url_test:
            name = is_url_test.group(1)
        
        # 设置默认前缀
        if not prefix:
            prefix = name + '-'
        
        subscriptions[name] = {
            'url': url,
            'prefix': prefix,
            'isUrlTest': bool(is_url_test)
        }
    
    return subscriptions

def generate_uuid():
    """生成UUID字符串"""
    return str(uuid.uuid4())

def get_random_error_response():
    """返回随机错误响应"""
    responses = [
        {'status': 401, 'message': '未经授权的访问被拒绝'},
        {'status': 403, 'message': '访问被禁止'},
        {'status': 404, 'message': '资源未找到'},
        {'status': 429, 'message': '请求频率过高'},
        {'status': 503, 'message': '服务不可用'}
    ]
    
    response = random.choice(responses)
    delay = random.randint(100, 2000)
    request_id = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    
    error_data = {
        'error': {
            'code': response['status'],
            'message': response['message'],
            'request_id': request_id,
            'timestamp': datetime.now().isoformat()
        }
    }
    
    headers = {
        'Content-Type': 'application/json',
        'X-Request-ID': request_id,
        'Retry-After': str(random.randint(30, 90)),
        'X-RateLimit-Remaining': '0'
    }
    
    return Response(
        json.dumps(error_data, ensure_ascii=False),# .encode('utf-8'),
        status=response['status'],
        headers=headers, # {k: str(v).encode('utf-8').decode('utf-8') for k, v in headers.items()},
        content_type='application/json; charset=utf-8'
    )

def process_nodes(nodes_text):
    """处理自建节点配置"""
    if not nodes_text or not nodes_text.strip():
        return []
    
    # 过滤有效节点URL
    node_urls = [
        line.strip() for line in nodes_text.split('\n') 
        if line.strip() and any(
            line.startswith(proto) 
            for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'tuic://']
        )
    ]
    
    return [node for node in (convert_node_to_clash_format(url) for url in node_urls) if node]

def convert_node_to_clash_format(node_url):
    """将节点URL转换为Clash配置格式"""
    try:
        parsed = urlparse(node_url)
        protocol = parsed.scheme
        hash_part = unquote(parsed.fragment) if parsed.fragment else None
        params = parse_qs(parsed.query)
        
        # 简化参数处理
        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        
        # 基本配置
        base_config = {
            'name': hash_part or f'自建-{generate_uuid()[:4]}',
            'server': parsed.hostname,
            'port': parsed.port if parsed.port else 443
        }

        # 根据不同协议处理
        if protocol == 'vless':
            flow = params.get('flow')
            if flow == 'xtls-rprx-direct':
                flow = None
                
            return {
                **base_config,
                'type': 'vless',
                'uuid': parsed.username,
                'cipher': params.get('encryption', 'none'),
                'tls': params.get('security') in ('tls', 'reality'),
                'client-fingerprint': params.get('fp', 'chrome'),
                'servername': params.get('sni', ''),
                'network': params.get('type', 'tcp'),
                'ws-opts': {
                    'path': params.get('path', '/'),
                    'headers': {'Host': params.get('host', parsed.hostname)}
                } if params.get('type') == 'ws' else None,
                'reality-opts': {
                    'public-key': params.get('pbk'),
                    'short-id': params.get('sid')
                } if params.get('security') == 'reality' else None,
                'grpc-opts': {
                    'grpc-mode': 'gun',
                    'grpc-service-name': params.get('serviceName')
                } if params.get('type') == 'grpc' else None,
                'flow': flow,
                'skip-cert-verify': False
            }
            
        elif protocol == 'trojan':
            return {
                **base_config,
                'type': 'trojan',
                'password': parsed.username,
                'tls': True,
                'client-fingerprint': params.get('fp', 'chrome'),
                'sni': params.get('sni', ''),
                'network': params.get('type', 'tcp'),
                'ws-opts': {
                    'path': params.get('path', '/'),
                    'headers': {'Host': params.get('host', parsed.hostname)}
                } if params.get('type') == 'ws' else None,
                'reality-opts': {
                    'public-key': params.get('pbk'),
                    'short-id': params.get('sid')
                } if params.get('security') == 'reality' else None,
                'skip-cert-verify': False
            }
            
        elif protocol == 'vmess':
            return {
                **base_config,
                'type': 'vmess',
                'port': int(params.get('port', 443)),
                'uuid': parsed.username,
                'alterId': int(params.get('aid', 0)),
                'cipher': params.get('encryption', 'auto'),
                'tls': params.get('security') == 'tls',
                'servername': params.get('sni', ''),
                'network': params.get('type', 'tcp'),
                'ws-opts': {
                    'path': params.get('path', '/'),
                    'headers': {'Host': params.get('host', parsed.hostname)}
                } if params.get('type') == 'ws' else None,
                'skip-cert-verify': False
            }
            
        elif protocol in ('ss', 'shadowsocks'):
            # 解码SS配置
            auth = base64.b64decode(parsed.username)#.decode('utf-8')
            method, password = auth.split(':', 1)
            
            return {
                **base_config,
                'type': 'ss',
                'cipher': method,
                'password': password
            }
            
        elif protocol == 'hysteria2':
            return {
                **base_config,
                'type': 'hysteria2',
                'password': parsed.username,
                'obfs': params.get('obfs'),
                'obfs-password': params.get('obfs-password', ''),
                'sni': params.get('sni', ''),
                'skip-cert-verify': params.get('insecure') == '1'
            }
            
        elif protocol == 'tuic':
            return {
                **base_config,
                'type': 'tuic',
                'uuid': params.get('uuid'),
                'password': params.get('password'),
                'congestion-controller': params.get('congestion', 'bbr'),
                'skip-cert-verify': False,
                'disable-sni': True,
                'alpn': params.get('alpn', '').split(','),
                'sni': params.get('sni', ''),
                'udp-relay-mode': 'native'
            }
            
        else:
            raise ValueError(f'不支持的协议: {protocol}')
            
    except Exception as e:
        print(f'转换节点时出错: {str(e)}')
        return None

def format_config(config):
    """将配置字典格式化为YAML字符串"""
    def needs_quotes(s):
        """检查字符串是否需要引号包裹"""
        if not isinstance(s, str):
            return False
        return any(c in s for c in ':{}[]"\'') or \
               bool(re.search(r'^[\s#:>|*{}\$\$\$\$,\'&?!]|-\s|:\s|^[+-]?\d+\.?\d*$', s)) or \
               any(emoji in s for emoji in ['🚀', '⚡', '📍', '➡']) or \
               len(s) == 0

    def format_value(v):
        """格式化单个值"""
        if v is None:
            return ''
        if isinstance(v, (bool, int, float)):
            return str(v).lower() if isinstance(v, bool) else str(v)
        if needs_quotes(v):
            return f'\"{str(v).replace("\"", "\\\"")}\"'
        return str(v)

    def to_yaml(obj, indent=0):
        """递归转换为YAML格式"""
        yaml_str = ''
        spaces = ' ' * indent
        
        for key, value in obj.items():
            if value is None:
                continue
                
            formatted_key = f'\"{key}\"' if needs_quotes(key) else key
            
            if isinstance(value, list):
                yaml_str += f'{spaces}{formatted_key}:\n'
                for item in value:
                    if isinstance(item, dict):
                        yaml_str += f'{spaces}- {to_yaml(item, indent + 2).lstrip()}\n'
                    else:
                        yaml_str += f'{spaces}- {format_value(item)}\n'
            elif isinstance(value, dict):
                yaml_str += f'{spaces}{formatted_key}:\n{to_yaml(value, indent + 2)}'
            else:
                yaml_str += f'{spaces}{formatted_key}: {format_value(value)}\n'
                
        return yaml_str
    
    return to_yaml(config)

@app.route('/')
@app.route('/<path:sub_path>')
def handle_request(sub_path=None):
    """处理所有请求"""
    # 从环境变量获取配置
    global token, subname, subupdatetime, subscriptions, nodes
    
    token = os.getenv('token', token)
    subscriptions = os.getenv('subscriptions', subscriptions)
    subname = os.getenv('subname', subname)
    subupdatetime = int(os.getenv('subupdatetime', subupdatetime))
    nodes = os.getenv('nodes', nodes)
    
    # 处理UUID请求
    if sub_path == 'uuid':
        return Response(
            generate_uuid(),
            content_type='text/plain; charset=utf-8',
            headers = {'Content-Type': 'text/plain; charset=utf-8'}

        )
    
    # 验证token
    if not sub_path or sub_path != token:
        return get_random_error_response()
    
    # 验证User-Agent
    user_agent = request.headers.get('User-Agent', '').lower()
    allowed_keywords = ['clash', 'meta', 'stash']
    banned_keywords = ['bot', 'spider']
    
    if (not any(k in user_agent for k in allowed_keywords) or
        any(k in user_agent for k in banned_keywords)):
        return get_random_error_response()
    
    # 解析订阅配置
    subs = parse_subscriptions(subscriptions)
    
    # 基础配置
    config = {
        "mixed-port": 7890,
        "ipv6": True,
        "allow-lan": True,
        "unified-delay": False,
        "tcp-concurrent": True,
        "external-controller": "127.0.0.1:9090",
        "external-ui": "ui",
        "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        "geodata-mode": True,
        "geox-url": {
            "geoip": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
            "geosite": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
            "mmdb": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
            "asn": "https://mirror.ghproxy.com/https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb"
        },
        "find-process-mode": "strict",
        "global-client-fingerprint": "chrome",
        "profile": {
            "store-selected": True,
            "store-fake-ip": True
        },
        "sniffer": {
            "enable": True,
            "sniff": {
                "HTTP": {
                    "ports": [80, "8080-8880"],
                    "override-destination": True
                },
                "TLS": {
                    "ports": [443, 8443]
                },
                "QUIC": {
                    "ports": [443, 8443]
                }
            },
            "skip-domain": [
                "Mijia Cloud",
                "+.push.apple.com"
            ]
        },
        "tun": {
            "enable": True,
            "stack": "mixed",
            "dns-hijack": [
                "any:53",
                "tcp://any:53"
            ],
            "auto-route": True,
            "auto-redirect": True,
            "auto-detect-interface": True
        },
        "dns": {
            "enable": True,
            "ipv6": True,
            "respect-rules": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-filter": [
                "*",
                "+.lan",
                "+.local",
                "+.market.xiaomi.com"
            ],
            "nameserver": [
                "https://223.5.5.5/dns-query",
                "https://120.53.53.53/dns-query"
            ],
            "proxy-server-nameserver": [
                "https://223.5.5.5/dns-query",
                "https://120.53.53.53/dns-query"
            ],
            "nameserver-policy": {
                "geosite:cn,private": [
                    "https://223.5.5.5/dns-query",
                    "https://120.53.53.53/dns-query"
                ],
                "geosite:geolocation-!cn": [
                    "https://dns.cloudflare.com/dns-query",
                    "https://dns.google/dns-query"
                ]
            }
        },
        "proxies": [
            {
                "name": "➡️ 直连",
                "type": "direct",
                "udp": True
            },
            {
                "name": "❌ 拒绝",
                "type": "reject"
            }
        ]
    }
    
    # 添加代理提供商配置
    config['proxy-providers'] = {}
    for name, sub in subs.items():
        config['proxy-providers'][name] = {
            'url': sub['url'],
            'type': 'http',
            'interval': 43200,
            'health-check': {
                'enable': True,
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300
            },
            'override': {
                'additional-prefix': sub['prefix']
            }
        }
        # 处理自建节点
        has_custom_nodes = nodes.strip() and len(process_nodes(nodes)) > 0
        self_hosted_group = None
        self_hosted_test_group = None

        if has_custom_nodes:
            custom_proxies = process_nodes(nodes)
            config['proxies'].extend(custom_proxies)

            self_hosted_group = {
                'name': '🏠 自建节点',
                'type': 'select',
                'proxies': [proxy['name'] for proxy in custom_proxies]
            }

            self_hosted_test_group = {
                'name': '🏠 自建节点(测速)',
                'type': 'url-test',
                'proxies': [proxy['name'] for proxy in custom_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50
            }

        # 代理组配置
        proxy_groups = [
            {
                'name': '🚀 默认',
                'type': 'select',
                'proxies': [
                    '⚡️ 自动选择',
                    '📍 全部节点',
                    *(['🏠 自建节点'] if has_custom_nodes else []),
                    *(['🏠 自建节点(测速)'] if has_custom_nodes else []),
                    *[f'📑 {name}' for name in subs.keys()],
                    '➡️ 直连',
                    '🇭🇰 香港',
                    '🇨🇳 台湾',
                    '🇯🇵 日本',
                    '🇸🇬 新加坡',
                    '🇺🇸 美国',
                    '🌐 其它地区'
                ]
            },
            {
                'name': '📍 全部节点',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject'
            },
            {
                'name': '⚡️ 自动选择',
                'type': 'url-test',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'tolerance': 10,
                'interval': 1200
            }
        ]

        # 添加自建节点组
        if self_hosted_group:
            proxy_groups.append(self_hosted_group)
            proxy_groups.append(self_hosted_test_group)

        # 为每个订阅源添加专属分组
        for name, sub in subs.items():
            group = {
                'name': f'📑 {name}',
                'type': 'url-test',# if sub['isUrlTest'] else 'select',
                "tolerance": 10,
                "interval": 1200,
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': f'(?i){sub["prefix"]}'
            }

            if sub['isUrlTest']:
                group.update({
                    'tolerance': 10,
                    'interval': 1200
                })

            proxy_groups.append(group)

        # 添加其他代理组
        proxy_groups.extend([
            {
                'name': '🚫 广告拦截',
                'type': 'select',
                'proxies': ['❌ 拒绝', '➡️ 直连', '🚀 默认']
            },
            {
                'name': '🇭🇰 香港',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)港|hk|hongkong|hong kong'
            },
            {
                'name': '🇨🇳 台湾',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)台|tw|taiwan'
            },
            {
                'name': '🇯🇵 日本',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)日|jp|japan'
            },
            {
                'name': '🇺🇸 美国',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)美|us|unitedstates|united states'
            },
            {
                'name': '🇸🇬 新加坡',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)(新|sg|singapore)'
            },
            {
                'name': '🔍 Google',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '📱 Telegram',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '🐦 Twitter',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '📺 哔哩哔哩',
                'type': 'select',
                'proxies': [
                    '➡️ 直连', '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾',
                    '🇯🇵 日本', '🇸🇬 新加坡', '🇺🇸 美国',
                    '🌐 其它地区', '📍 全部节点', '⚡️ 自动选择'
                ]
            },
            {
                'name': '📹 YouTube',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '🎬 NETFLIX',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '🎵 Spotify',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '📦 Github',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '🌏 国内',
                'type': 'select',
                'proxies': [
                    '➡️ 直连', '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾',
                    '🇯🇵 日本', '🇸🇬 新加坡', '🇺🇸 美国',
                    '🌐 其它地区', '📍 全部节点', '⚡️ 自动选择'
                ]
            },
            {
                'name': '🌍 其他',
                'type': 'select',
                'proxies': [
                    '🚀 默认', '🇭🇰 香港', '🇨🇳 台湾', '🇯🇵 日本',
                    '🇸🇬 新加坡', '🇺🇸 美国', '🌐 其它地区',
                    '📍 全部节点', '⚡️ 自动选择', '➡️ 直连'
                ]
            },
            {
                'name': '🌐 其它地区',
                'type': 'select',
                'include-all': True,
                'exclude-type': 'direct|reject',
                'filter': '(?i)^(?!.*(?:🇭🇰|🇯🇵|🇺🇸|🇸🇬|🇨🇳|港|hk|hongkong|台|tw|taiwan|日|jp|japan|新|sg|singapore|美|us|unitedstates)).*'
            }
        ])

        config['proxy-groups'] = proxy_groups

        # 规则配置
        config['rules'] = [
            "GEOSITE,category-ads-all,🚫 广告拦截",
            "GEOIP,lan,➡️ 直连,no-resolve",
            "GEOSITE,github,📦 Github",
            "GEOSITE,twitter,🐦 Twitter",
            "GEOSITE,youtube,📹 YouTube",
            "GEOSITE,google,🔍 Google",
            "GEOSITE,telegram,📱 Telegram",
            "GEOSITE,netflix,🎬 NETFLIX",
            "GEOSITE,bilibili,📺 哔哩哔哩",
            "GEOSITE,spotify,🎵 Spotify",
            "GEOSITE,CN,🌏 国内",
            "GEOSITE,geolocation-!cn,🌍 其他",
            "GEOIP,google,🔍 Google",
            "GEOIP,netflix,🎬 NETFLIX",
            "GEOIP,telegram,📱 Telegram",
            "GEOIP,twitter,🐦 Twitter",
            "GEOIP,CN,🌏 国内,no-resolve",
            "MATCH,🌍 其他"
        ]
    # 生成YAML配置
    yaml_config = format_config(config)

    # 修正Content-Disposition头
    encoded_subname = quote(subname, safe='')
    base_filename = f"{encoded_subname}.yaml"
    content_disposition = (
        f"attachment; "
        f"filename=\"{base_filename}\"; "  # ASCII兼容的文件名
        f"filename*=UTF-8''{encoded_subname}.yaml"  # UTF-8编码的中文文件名
    )

    return Response(
        yaml_config,
        content_type='text/yaml; charset=utf-8',
        headers={
            'Profile-Update-Interval': str(subupdatetime),
            'Content-Disposition': content_disposition
        }
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)