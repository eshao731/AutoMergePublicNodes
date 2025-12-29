#!/usr/bin/env python3
# pyright: reportConstantRedefinition = none
# pyright: reportMissingTypeStubs = none
# pyright: reportRedeclaration = none
# pyright: reportMissingParameterType = none
# pyright: reportUnnecessaryIsInstance = none
# pyright: reportUnknownVariableType = none
# pyright: reportUnknownMemberType = none
# pyright: reportUnknownArgumentType = none
# pyright: reportArgumentType = none
# pyright: reportAttributeAccessIssue = none
# pyright: reportGeneralTypeIssues = none
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
from requests_file import FileAdapter
import datetime
import traceback
import binascii
import threading
import sys
import os
import copy
import socket
import time
import subprocess
import tempfile
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import FunctionType as function
from typing import Set, List, Dict, Tuple, Union, Callable, Any, Optional, no_type_check

# 源历史记录相关常量
SOURCE_HISTORY_FILE = "source_history.json"
SOURCE_DELETE_FILE = "source_delete.list"
SOURCES_FILE = "sources.list"
INVALID_DAYS_THRESHOLD = 7  # 连续无效天数阈值

try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else:
    if not PROXY: PROXY = None
    LOCAL = not PROXY

def b64encodes(s: str):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def b64decodes_safe(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id', 
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH: Dict[str, str] = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_EXAMPLE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

ABFURLS = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    # "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    # "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
    # "https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt",
    # "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    # "https://anti-ad.net/adguard.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    # "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    # "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_lite.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/domain.txt",
)

ABFWHITE = (
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///abpwhite.txt",
)

FAKE_IPS = "8.8.8.8; 8.8.4.4; 4.2.2.2; 4.2.2.1; 114.114.114.114; 127.0.0.1; 0.0.0.0".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

FETCH_TIMEOUT = (6, 5)

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8gb25ndGFpd2Fu').split()

# !!! JUST FOR DEBUGING !!!
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_DYNAMIC = os.path.exists("local_NO_DYNAMIC")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

STOP = False
STOP_FAKE_NODES = """vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NUU4Nlx1Nzk1RFx1NEU5QVx1NTFBQ1x1NEYxQVx1ODBEQ1x1NTIyOVx1NTNFQ1x1NUYwMCIsDQogICJhZGQiOiAid2ViLjUxLmxhIiwNCiAgInBvcnQiOiAiNDQzIiwNCiAgImlkIjogIjg4ODg4ODg4LTg4ODgtODg4OC04ODg4LTg4ODg4ODg4ODg4OCIsDQogICJhaWQiOiAiMCIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAidGNwIiwNCiAgInR5cGUiOiAiaHR0cCIsDQogICJob3N0IjogIndlYi41MS5sYSIsDQogICJwYXRoIjogIi9pbWFnZXMvaW5kZXgvc2VydmljZS1waWMucG5nIiwNCiAgInRscyI6ICJ0bHMiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NjU0Rlx1NjExRlx1NjVGNlx1NjcxRlx1RkYwQ1x1NjZGNFx1NjVCMFx1NjY4Mlx1NTA1QyIsDQogICJhZGQiOiAid2ViLjUxLmxhIiwNCiAgInBvcnQiOiAiNDQzIiwNCiAgImlkIjogImM2ZTg0MDcyLTJlNjktNDkyOC05MGFmLTQzNmIzZmNkMDY2MyIsDQogICJhaWQiOiAiMCIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAidGNwIiwNCiAgInR5cGUiOiAiaHR0cCIsDQogICJob3N0IjogIndlYi41MS5sYSIsDQogICJwYXRoIjogIi9pbWFnZXMvaW5kZXgvc2VydmljZS1waWMucG5nIiwNCiAgInRscyI6ICJ0bHMiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NTk4Mlx1NjcwOVx1OTcwMFx1ODk4MVx1RkYwQ1x1ODFFQVx1ODg0Q1x1NjQyRFx1NUVGQSIsDQogICJhZGQiOiAid2ViLjUxLmxhIiwNCiAgInBvcnQiOiAiNDQzIiwNCiAgImlkIjogImUwYzZiM2I3LTlmNWItNGJkNi05YWJmLTI2MDY2M2FhNGYxYiIsDQogICJhaWQiOiAiMCIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAidGNwIiwNCiAgInR5cGUiOiAiaHR0cCIsDQogICJob3N0IjogIndlYi41MS5sYSIsDQogICJwYXRoIjogIi9pbWFnZXMvaW5kZXgvc2VydmljZS1waWMucG5nIiwNCiAgInRscyI6ICJ0bHMiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
"""

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

session = requests.Session()
session.trust_env = False
if PROXY: session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.0.3 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
session.mount('file://', FileAdapter())
    
exc_queue: List[str] = []

d = datetime.datetime.now()
if STOP or (d.month, d.day) in ((6, 4), (7, 1), (10, 1)):
    DEBUG_NO_NODES = DEBUG_NO_DYNAMIC = STOP = True

class Node:
    names: Set[str] = set()
    DATA_TYPE = Dict[str, Any]

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: __class__.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else: raise TypeError(f"Got {type(data)}")
        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.name: str = self.data['name']

    def __str__(self):
        return self.url

    def __hash__(self):
        data = self.data
        try:
            path = ""
            if self.type == 'vmess':
                net: str = data.get('network', '')
                path = net+':'
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'h2':
                    opts: Dict[str, Any] = data.get('h2-opts', {})
                    path += ','.join(opts.get('host', []))
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'ss':
                opts: Dict[str, Any] = data.get('plugin-opts', {})
                path = opts.get('host', '')
                path += '/'+opts.get('path', '')
            elif self.type == 'ssr':
                path = data.get('obfs-param', '')
            elif self.type == 'trojan':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'vless':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'hysteria2':
                path = data.get('sni', '')+':'
                path += data.get('obfs-password', '')+':'
                # print(self.url)
                # return hash(self.url)
            path += '@'+','.join(data.get('alpn', []))+'@'+data.get('password', '')+data.get('uuid', '')
            hashstr = f"{self.type}:{data['server']}:{data['port']}:{path}"
            return hash(hashstr)
        except Exception:
            print("节点 Hash 计算失败！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return hash('__ERROR__')
    
    def __eq__(self, other: Union['Node', Any]):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    def load_url(self, url: str) -> None:
        try: self.type, dt = url.split("://", 1)
        except ValueError: raise NotANode(url)
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        if self.type == 'hy2': self.type = 'hysteria2'
        # === Fix end ===
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            try: v.update(json.loads(b64decodes(dt)))
            except Exception:
                raise UnsupportedType('vmess', 'SP')
            self.data = {}
            for key, val in v.items():
                if key in VMESS2CLASH:
                    self.data[VMESS2CLASH[key]] = val
            self.data['tls'] = (v['tls'] == 'tls')
            # 安全地转换 alterId，处理无效值
            try:
                self.data['alterId'] = int(self.data['alterId'])
            except (ValueError, KeyError):
                self.data['alterId'] = 0  # 默认值为 0
            if v['net'] == 'ws':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['headers'] = {'Host': v['host']}
                self.data['ws-opts'] = opts
            elif v['net'] == 'h2':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['host'] = v['host'].split(',')
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}

        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            if '#' in srvname:
                srv, name = srvname.split('#')
            else:
                srv = srvname
                name = ''
            server, port = srv.split(':')
            try:
                port = int(port)
            except ValueError:
                raise UnsupportedType('ss', 'SP')
            info = '@'.join(info)
            if not ':' in info:
                info = b64decodes_safe(info)
            if ':' in info:
                cipher, passwd = info.split(':', 1)  # 使用 maxsplit=1 来处理密码中包含 : 的情况
            else:
                cipher = info
                passwd = ''
            self.data = {'name': unquote(name), 'server': server,
                    'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

        elif self.type == 'ssr':
            if '?' in url:
                parts = dt.split(':')
            else:
                parts = b64decodes_safe(dt).split(':')
            try:
                passwd, info = parts[-1].split('/?')
            except: raise
            passwd = b64decodes_safe(passwd)
            self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                    'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                    'password': passwd, 'name': ''}
            for kv in info.split('&'):
                k_v = kv.split('=')
                if len(k_v) != 2:
                    k = k_v[0]
                    v = ''
                else: k,v = k_v
                if k == 'remarks':
                    self.data['name'] = v
                elif k == 'group':
                    self.data['group'] = v
                elif k == 'obfsparam':
                    self.data['obfs-param'] = v
                elif k == 'protoparam':
                    self.data['protocol-param'] = v

        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname, 
                    'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)} # type: ignore
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k,v = kv.split('=')
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni': self.data['sni'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v

        elif self.type == 'vless':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname, 
                    'port': parsed.port, 'type': 'vless', 'uuid': unquote(parsed.username)} # type: ignore
            self.data['tls'] = False
            if parsed.query:
                for kv in parsed.query.split('&'):
                    if '=' not in kv:
                        continue
                    k, v = kv.split('=', 1)  # 使用 maxsplit=1 来处理值中包含 = 的情况
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni': self.data['servername'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
                    elif k == 'flow':
                        if v.endswith('-udp443'):
                            self.data['flow'] = v
                        else: self.data['flow'] = v+'!'
                    elif k == 'fp': self.data['client-fingerprint'] = v
                    elif k == 'security' and v == 'tls':
                        self.data['tls'] = True
                    elif k == 'pbk':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['public-key'] = v
                    elif k == 'sid':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['short-id'] = v
                    # TODO: Unused key encryption

        elif self.type == 'hysteria2':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname, 
                    'type': 'hysteria2', 'password': unquote(parsed.username)} # type: ignore
            if ':' in parsed.netloc:
                ports = parsed.netloc.split(':')[1]
                if ',' in ports:
                    self.data['port'], self.data['ports'] = ports.split(',',1)
                else:
                    self.data['port'] = ports
                try: self.data['port'] = int(self.data['port'])
                except ValueError: self.data['port'] = 443
            else:
                self.data['port'] = 443
            self.data['tls'] = False
            if parsed.query:
                k = v = ''
                for kv in parsed.query.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=', 1)  # 使用 maxsplit=1 来处理值中包含 = 的情况
                    else:
                        v += '&' + kv
                    if k == 'insecure':
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k in ('sni', 'obfs', 'obfs-password'):
                        self.data[k] = v
                    elif k == 'fp': self.data['fingerprint'] = v
        
        else: raise UnsupportedType(self.type)

    def format_name(self, max_len=30) -> None:
        import re

        self.data['name'] = self.name

        # 1. 去除节点名称中的广告

        # 1.1 去除括号内包含域名的广告
        ad_patterns = [
            r'\([^)]*\.(com|cn|net|top|xyz|org|cc|me|io|co|info|biz|vip|club|online|site|tech|store|fun|icu|link|pro|live|wang|work|to)[^)]*\)',  # 英文括号
            r'（[^）]*\.(com|cn|net|top|xyz|org|cc|me|io|co|info|biz|vip|club|online|site|tech|store|fun|icu|link|pro|live|wang|work|to)[^）]*）',  # 中文括号
            r'\[[^\]]*\.(com|cn|net|top|xyz|org|cc|me|io|co|info|biz|vip|club|online|site|tech|store|fun|icu|link|pro|live|wang|work|to)[^\]]*\]',  # 方括号
            r'【[^】]*\.(com|cn|net|top|xyz|org|cc|me|io|co|info|biz|vip|club|online|site|tech|store|fun|icu|link|pro|live|wang|work|to)[^】]*】',  # 中文方括号
        ]

        for pattern in ad_patterns:
            self.data['name'] = re.sub(pattern, '', self.data['name'], flags=re.IGNORECASE)

        # 1.2 去除直接包含的网址（如：官网❶https://kelayu 或 官网❷https://99z.to）
        # 匹配 http:// 或 https:// 开头的网址，以及前面可能的文字
        url_patterns = [
            r'@\w+',
            r'机场',
            r'机场推荐',
            r'https?://[^\s]+',  # 匹配完整的URL
            r'官网[❶❷❸❹❺❻❼❽❾❿⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾①②③④⑤⑥⑦⑧⑨⑩\d]*[^\s]*',  # 匹配"官网"及其后面的内容
            r'[^\s]*\.(com|cn|net|top|xyz|org|cc|me|io|co|info|biz|vip|club|online|site|tech|store|fun|icu|link|pro|live|wang|work|to)/?[^\s]*',  # 匹配域名
        ]

        for pattern in url_patterns:
            self.data['name'] = re.sub(pattern, '', self.data['name'], flags=re.IGNORECASE)

        # 1.3 去除恶意文字和不良内容
        # 只删除恶意词汇本身，不删除整个词组
        offensive_words = [
            r'只.*?不.*?买.*?的.*',  # "只...不买的..."句式（放在最前面，优先匹配）
            r'白嫖[^\s]*',  # 白嫖及其后续
            r'死.*?家',  # 死全家等
            r'傻[逼比]',  # 脏话
            r'[操草][你泥][妈吗马]',  # 脏话
            r'滚蛋',  # 不礼貌词汇
            r'不买的.*',  # "不买的..."
        ]

        for pattern in offensive_words:
            self.data['name'] = re.sub(pattern, '', self.data['name'], flags=re.IGNORECASE)

        # 清理多余的空格和特殊字符（包括常见的广告emoji）
        self.data['name'] = ' '.join(self.data['name'].split())
        self.data['name'] = self.data['name'].strip(' -_|👖🎁🎉🎊💎⭐🌟✨')

        # 2. 使用原有的 BANNED_WORDS 过滤
        for word in BANNED_WORDS:
            self.data['name'] = self.data['name'].replace(word, '*'*len(word))

        # 3. 添加品牌标识 uu6.top
        # 使用后缀方式，不影响地区关键词识别
        brand = "uu6.top"
        # 计算添加品牌后的长度，确保不超过限制
        if self.data['name']:
            # 如果名称太短，直接添加；如果太长，先截断再添加
            available_len = max_len - len(f" | {brand}")
            if len(self.data['name']) > available_len:
                self.data['name'] = self.data['name'][:available_len].rstrip()
            self.data['name'] = f"{self.data['name']} | {brand}"
        else:
            # 如果名称为空，使用默认名称
            self.data['name'] = f"未命名 | {brand}"

        # 4. 处理重名
        if self.data['name'] in Node.names:
            i = 0
            new: str = self.data['name']
            while new in Node.names:
                i += 1
                new = f"{self.data['name']} #{i}"
            self.data['name'] = new
        
    @property
    def isfake(self) -> bool:
        try:
            if 'server' not in self.data: return True
            if '.' not in self.data['server']: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            # TODO: Fake UUID
            # if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            #     return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                # That's not designed for China
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    @property
    def url(self) -> str:
        data = self.data
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            for key,val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

        if self.type == 'ss':
            passwd = b64encodes_safe(data['cipher']+':'+data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        if self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server','port',
                                        'protocol','cipher','obfs')]) +
                    b64encodes_safe(self.data['password']) +
                    f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
                if k in self.data:
                    ret += '&'+urlk+'='+b64encodes_safe(self.data[k])
            return "ssr://"+ret

        if self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    service_name = data.get('grpc-opts', {}).get('grpc-service-name', '')
                    ret += f"type=grpc&serviceName={service_name}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&')+'#'+name
            return ret

        if self.type == 'vless':
            passwd = quote(data['uuid'])
            name = quote(data['name'])
            ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'servername' in data:
                ret += f"sni={data['servername']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    service_name = data.get('grpc-opts', {}).get('grpc-service-name', '')
                    ret += f"type=grpc&serviceName={service_name}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            if 'flow' in data:
                flow: str = data['flow']
                if flow.endswith('!'):
                    ret += f"flow={flow[:-1]}&"
                else: ret += f"flow={flow}-udp443&"
            if 'client-fingerprint' in data:
                ret += f"fp={data['client-fingerprint']}&"
            if 'tls' in data and data['tls']:
                ret += f"security=tls&"
            elif 'reality-opts' in data:
                opts: Dict[str, str] = data['reality-opts']
                ret += f"security=reality&pbk={opts.get('public-key','')}&sid={opts.get('short-id','')}&"
            ret = ret.rstrip('&')+'#'+name
            return ret

        if self.type == 'hysteria2':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
            if 'ports' in data:
                ret += ','+data['ports']
            ret += '?'
            if 'skip-cert-verify' in data:
                ret += f"insecure={int(data['skip-cert-verify'])}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'fingerprint' in data:
                ret += f"fp={data['fingerprint']}&"
            for k in ('sni', 'obfs', 'obfs-password'):
                if k in data:
                    ret += f"{k}={data[k]}&"
            ret = ret.rstrip('&')+'#'+name
            return ret

        raise UnsupportedType(self.type)

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret: del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            # 'alpn' is not a slice
            ret['alpn'] = ret['alpn'].replace(' ','').split(',')
        return ret

    def supports_meta(self, noMeta=False) -> bool:
        if self.isfake: return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        elif noMeta: return False
        else: return True
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            # A quick fix for #2
            self.data['tls'] = True
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        if self.data['cipher'] not in supported: return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                    and not self.data['plugin-opts']['mode']: return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return False
        return True
    
    def supports_clash(self, meta=False) -> bool:
        if meta: return self.supports_meta()
        if self.type == 'vless': return False
        if self.data['type'] == 'vless': return False
        return self.supports_meta(noMeta=True)

    def supports_ray(self) -> bool:
        if self.isfake: return False
        # if self.type == 'ss':
        #     if 'plugin' in self.data and self.data['plugin']: return False
        # elif self.type == 'ssr':
        #     return False
        return True

class Source():
    @no_type_check
    def __init__(self, url: Union[str, function]) -> None:
        if isinstance(url, function):
            self.url: str = "dynamic://"+url.__name__
            self.url_source: function = url
        elif url.startswith('+'):
            self.url_source: str = url
            self.date = datetime.datetime.now()# + datetime.timedelta(days=1)
            self.gen_url()
        else:
            self.url: str = url
            self.url_source: None = None
        self.content: Union[str, List[str], int] = None
        self.sub: Union[List[str], List[Dict[str, str]]] = None
        self.cfg: Dict[str, Any] = {}

    def gen_url(self) -> None:
        self.url_source: str
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    @no_type_check
    def get(self, depth=2) -> None:
        global exc_queue
        if self.content: return
        try:
            if self.url.startswith("dynamic:"):
                self.content: Union[str, List[str]] = self.url_source()
            else:
                global session
                if '#' in self.url:
                    segs = self.url.split('#')
                    self.cfg = dict([_.split('=',1) for _ in segs[-1].split('&')])
                    if 'max' in self.cfg:
                        try:
                            self.cfg['max'] = int(self.cfg['max'])
                        except ValueError:
                            exc_queue.append("最大节点数限制不是整数！")
                            del self.cfg['max']
                    if 'ignore' in self.cfg:
                        self.cfg['ignore'] = [_ for _ in self.cfg['ignore'].split(',') if _.strip()]
                    self.url = '#'.join(segs[:-1])
                with session.get(self.url, stream=True) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t"+self.url
                            exc_queue.append(exc)
                            self.get(depth-1)
                        else:
                            self.content = r.status_code
                        return
                    self.content = self._download(r)
        except KeyboardInterrupt: raise
        except requests.exceptions.RequestException:
            self.content = -1
        except:
            self.content = -2
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            exc_queue.append(exc)
        else:
            self.parse()

    def _download(self, r: requests.Response) -> str:
        content: str = ""
        tp = None
        pending = None
        early_stop = False
        for chunk in r.iter_content():
            if early_stop: pending = None; break
            chunk: bytes
            if pending is not None:
                chunk = pending + chunk
                pending = None
            if tp == 'sub':
                content += chunk.decode(errors='ignore')
                continue
            lines: List[bytes] = chunk.splitlines()
            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            while lines:
                line = lines.pop(0).rstrip().decode(errors='ignore').replace('\\r','')
                if not line: continue
                if not tp:
                    if ': ' in line:
                        kv = line.split(': ')
                        if len(kv) == 2 and kv[0].isalpha():
                            tp = 'yaml'
                    elif line[0] == '#': pass
                    else: tp = 'sub'
                if tp == 'yaml':
                    if content:
                        if line in ("proxy-groups:", "rules:", "script:"):
                            early_stop=True; break
                        content += line+'\n'
                    elif line == "proxies:":
                        content = line+'\n'
                elif tp == 'sub':
                    content = chunk.decode(errors='ignore')
        if pending is not None: content += pending.decode(errors='ignore')
        return content

    def parse(self) -> None:
        global exc_queue
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    # Clash config
                    config = yaml.full_load(text.replace("!<str>","!!str"))
                    sub = config['proxies']
                elif '://' in text:
                    # V2Ray raw list
                    sub = text.strip().splitlines()
                else:
                    # V2Ray Sub
                    try:
                        sub = b64decodes(text.strip()).strip().splitlines()
                    except (UnicodeDecodeError, binascii.Error) as e:
                        exc_queue.append(f"base64 解码失败: {type(e).__name__}")
                        self.sub = []
                        return
            else: sub = text # 动态节点抓取后直接传入列表

            if 'max' in self.cfg and len(sub) > self.cfg['max']:
                exc_queue.append(f"此订阅有 {len(sub)} 个节点，最大限制为 {self.cfg['max']} 个，忽略此订阅。")
                self.sub = []
            elif sub and 'ignore' in self.cfg:
                if isinstance(sub[0], str):
                    self.sub = [_ for _ in sub if _.split('://', 1)[0] not in self.cfg['ignore']]
                elif isinstance(sub[0], dict):
                    self.sub = [_ for _ in sub if _.get('type', '') not in self.cfg['ignore']] #type:ignore
                else: self.sub = sub
            else: self.sub = sub
        except KeyboardInterrupt: raise
        except: exc_queue.append(
                "在解析 '"+self.url+"' 时发生错误：\n"+traceback.format_exc())

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]) -> None:
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = __class__()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]) -> None:
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here: ret.append(name)
            else: ret.extend([_+'.'+name for _ in child.get()])
        return ret

def extract(url: str) -> Union[Set[str], int]:
    global session
    res = session.get(url)
    if res.status_code != 200: return res.status_code
    urls: Set[str] = set()
    if '#' in url:
        mark = '#'+url.split('#', 1)[1]
    else:
        mark = ''
    for line in res.text.strip().splitlines():
        if line.startswith("http"):
            urls.add(line+mark)
    return urls

merged: Dict[int, Node] = {}
unknown: Set[str] = set()
used: Dict[int, Dict[int, str]] = {}
def merge(source_obj: Source, sourceId=-1) -> None:
    global merged, unknown
    sub = source_obj.sub
    if not sub: print("空订阅，跳过！", end='', flush=True); return
    for p in sub:
        if isinstance(p, str) and '://' not in p: continue
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p) # type: ignore
        except Exception as e:
            # 打印错误类型和简短信息
            error_type = type(e).__name__
            error_msg = str(e)
            # 打印解析失败的数据（截取前100个字符）
            data_preview = str(p)[:100] if isinstance(p, str) else str(p)[:100]
            print(f"解析节点失败 ({error_type}: {error_msg}) - 数据: {data_preview}", flush=True)
        else:
            n.format_name()
            Node.names.add(n.data['name'])
            hashn = hash(n)
            if hashn not in merged:
                merged[hashn] = n
            else:
                merged[hashn].data.update(n.data)
            if hashn not in used:
                used[hashn] = {}
            used[hashn][sourceId] = n.name

def raw2fastly(url: str) -> str:
    if not LOCAL: return url
    url: Union[str, List[str]]
    if url.startswith("https://raw.githubusercontent.com/"):
        # url = url[34:].split('/')
        # url[1] += '@'+url[2]
        # del url[2]
        # url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
        # return url
        return "https://ghproxy.cn/"+url
    return url

def test_node_delay(node: Node, timeout: float = 1.0) -> Optional[float]:
    """
    测试节点的TCP连接延迟
    返回延迟时间（秒），失败返回None
    """
    try:
        server = node.data.get('server')
        port = node.data.get('port')

        if not server or not port:
            return None

        # 尝试将端口转换为整数
        try:
            port = int(port)
        except (ValueError, TypeError):
            return None

        # 测试TCP连接
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((server, port))
            delay = time.time() - start_time
            sock.close()
            return delay
        except (socket.timeout, socket.error, OSError):
            return None
        finally:
            try:
                sock.close()
            except:
                pass
    except Exception:
        return None

def find_clash_executable() -> Optional[str]:
    """
    查找系统中的Clash可执行文件
    优先使用环境变量CLASH_BINARY指定的路径
    """
    # 优先使用环境变量指定的路径
    clash_binary = os.environ.get('CLASH_BINARY')
    if clash_binary and os.path.isfile(clash_binary) and os.access(clash_binary, os.X_OK):
        return clash_binary

    # 在PATH中查找
    possible_names = ['mihomo', 'clash-meta', 'clash.meta', 'clash']

    for name in possible_names:
        path = shutil.which(name)
        if path:
            return path

    return None

def test_nodes_with_clash(nodes_dict: Dict[int, Node], max_delay: int = 1000, test_urls: Optional[List[str]] = None, max_retries: int = 1, concurrent_tests: int = 15) -> Dict[int, Node]:
    """
    使用Clash API测试节点延迟
    这是最准确的测试方法，会实际通过代理发送请求

    参数:
        nodes_dict: 节点字典
        max_delay: 最大延迟（毫秒）
        test_urls: 测试URL列表，会依次尝试直到成功
        max_retries: 每个URL的最大重试次数
        concurrent_tests: 并发测试数量
    """
    # 检测是否在GitHub Actions环境
    is_github_actions = os.environ.get('GITHUB_ACTIONS') == 'true'

    # 默认使用多个测试URL，提高测试成功率
    if test_urls is None:
        if is_github_actions:
            # GitHub Actions环境：使用国外URL
            test_urls = [
                "http://www.gstatic.com/generate_204",
                "http://cp.cloudflare.com/generate_204"
            ]
        else:
            # 本地环境：优先使用国内外都可访问的URL
            test_urls = [
                "http://cp.cloudflare.com/generate_204",
                "http://www.gstatic.com/generate_204",
                "http://captive.apple.com/hotspot-detect.html"
            ]

    clash_bin = find_clash_executable()
    if not clash_bin:
        print("=" * 60)
        print("警告：未找到Clash可执行文件")
        print("将使用TCP连接测试（不如Clash API测试准确）")
        print("提示：在GitHub Actions中会自动下载mihomo进行测试")
        print("=" * 60)
        return filter_nodes_by_delay_tcp(nodes_dict, max_delay=max_delay/1000.0)

    print(f"使用 {os.path.basename(clash_bin)} 测试节点延迟（这可能需要几分钟）...")

    # 创建临时目录和配置文件
    temp_dir = tempfile.mkdtemp(prefix='clash_test_')
    config_path = os.path.join(temp_dir, 'config.yaml')

    try:
        # 生成Clash配置，过滤掉有问题的节点
        proxies = []
        node_names = {}
        skipped = 0
        skipped_reasons = {}
        for hash_id, node in nodes_dict.items():
            if node.supports_meta():
                proxy_data = node.clash_data
                skip_reason = None
                
                # 验证 REALITY 配置
                if 'reality-opts' in proxy_data:
                    opts = proxy_data.get('reality-opts', {})
                    short_id = opts.get('short-id', '')
                    public_key = opts.get('public-key', '')
                    
                    # public-key 是必须的
                    if not public_key:
                        skip_reason = "REALITY缺少public-key"
                    # short-id 必须是有效的十六进制，且长度必须是 0, 8, 或 16（mihomo要求）
                    elif short_id:
                        valid_lengths = [0, 8, 16]
                        try:
                            bytes.fromhex(short_id)
                            if len(short_id) not in valid_lengths:
                                skip_reason = f"REALITY short-id长度无效({len(short_id)})"
                        except ValueError:
                            skip_reason = f"REALITY short-id格式无效"
                
                if skip_reason:
                    skipped += 1
                    skipped_reasons[skip_reason] = skipped_reasons.get(skip_reason, 0) + 1
                    continue
                    
                proxies.append(proxy_data)
                node_names[node.data['name']] = (hash_id, node)
        
        if skipped > 0:
            print(f"跳过 {skipped} 个配置无效的节点:")
            for reason, count in skipped_reasons.items():
                print(f"  - {reason}: {count}个")

        # 完善的Clash配置，包含DNS设置
        config = {
            'port': 17890,
            'socks-port': 17891,
            'allow-lan': False,
            'mode': 'global',
            'log-level': 'silent',
            'external-controller': '127.0.0.1:19090',
            'dns': {
                'enable': True,
                'listen': '0.0.0.0:1053',
                'enhanced-mode': 'fake-ip',
                'nameserver': [
                    '223.5.5.5',
                    '119.29.29.29',
                    '8.8.8.8',
                    '1.1.1.1'
                ],
                'fallback': [
                    'https://1.1.1.1/dns-query',
                    'https://dns.google/dns-query'
                ]
            },
            'proxies': proxies
        }

        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)

        # 先测试配置文件是否有效
        print(f"测试配置文件（共 {len(proxies)} 个节点）...")
        # 输出前10个节点的信息用于调试
        for i, p in enumerate(proxies[:10]):
            has_reality = 'reality-opts' in p
            reality_info = ""
            if has_reality:
                opts = p.get('reality-opts', {})
                sid = opts.get('short-id', '<无>')
                pbk = opts.get('public-key', '<无>')[:20] if opts.get('public-key') else '<无>'
                reality_info = f" sid={sid} pbk={pbk}..."
            print(f"  节点{i}: {p.get('name', 'unknown')[:30]} type={p.get('type')} reality={has_reality}{reality_info}")
        test_result = subprocess.run(
            [clash_bin, '-t', '-f', config_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if test_result.returncode != 0:
            print(f"配置文件测试失败，退出码: {test_result.returncode}")
            print(f"错误输出: {test_result.stderr[:2000] if test_result.stderr else '无'}")
            print(f"标准输出: {test_result.stdout[:2000] if test_result.stdout else '无'}")
            print("=" * 60)
            print("将返回 None，使用上次的节点")
            print("=" * 60)
            return None

        # 启动Clash进程
        print(f"启动Clash进程...")
        process = subprocess.Popen(
            [clash_bin, '-d', temp_dir, '-f', config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # 等待Clash启动并检查API是否可用
        api_base = 'http://127.0.0.1:19090'
        startup_retries = 30  # 增加等待时间
        clash_started = False
        for i in range(startup_retries):
            # 检查进程是否已退出
            if process.poll() is not None:
                stderr_output = process.stderr.read().decode('utf-8', errors='ignore')
                print(f"错误：Clash进程意外退出，退出码: {process.returncode}")
                if stderr_output:
                    print(f"错误信息: {stderr_output[:500]}")
                break
            try:
                response = requests.get(f"{api_base}/version", timeout=2)
                if response.status_code == 200:
                    print(f"Clash已启动，版本: {response.json().get('version', 'unknown')}")
                    clash_started = True
                    break
            except:
                pass
            time.sleep(1)  # 增加每次等待时间
        
        if not clash_started:
            print("=" * 60)
            print("错误：Clash启动失败，无法进行节点测试")
            # 尝试读取错误输出
            try:
                stderr_output = process.stderr.read().decode('utf-8', errors='ignore')
                if stderr_output:
                    print(f"Clash错误输出: {stderr_output[:1000]}")
            except:
                pass
            print("提示：这可能是 GitHub Actions 环境限制导致的")
            print("将返回 None，使用上次的节点")
            print("=" * 60)
            return None

        # 测试节点（使用并发）
        valid_nodes: Dict[int, Node] = {}
        total = len(node_names)
        tested = 0
        valid = 0
        error_stats: Dict[str, int] = {}
        test_lock = threading.Lock()

        print(f"开始测试 {total} 个节点的延迟")
        print(f"  - 超时时间: {max_delay}ms")
        print(f"  - 测试URL: {len(test_urls)}个备选")
        print(f"  - 重试次数: {max_retries}次")
        print(f"  - 并发数: {concurrent_tests}")
        print(f"  - 环境: {'GitHub Actions' if is_github_actions else '本地'}")
        print("-" * 60)

        def test_single_node(name: str, hash_id: int, node: Node) -> Tuple[bool, Optional[int], Optional[str]]:
            """测试单个节点，返回(是否有效, 延迟, 错误信息)"""
            from urllib.parse import quote as url_quote
            encoded_name = url_quote(name)

            # 尝试多个测试URL
            for test_url in test_urls:
                # 对每个URL进行重试
                for retry in range(max_retries):
                    try:
                        url = f"{api_base}/proxies/{encoded_name}/delay?timeout={max_delay}&url={test_url}"
                        response = requests.get(url, timeout=max_delay/1000.0 + 10)

                        if response.status_code == 200:
                            data = response.json()
                            delay = data.get('delay', 0)
                            if delay > 0 and delay <= max_delay:
                                return True, delay, None
                            else:
                                last_error = f"延迟过高({delay}ms)"
                        else:
                            try:
                                error_data = response.json()
                                last_error = error_data.get('message', f'HTTP {response.status_code}')
                            except:
                                last_error = f'HTTP {response.status_code}'

                    except requests.exceptions.Timeout:
                        last_error = "Timeout"
                    except requests.exceptions.ConnectionError:
                        last_error = "连接错误"
                    except Exception as e:
                        last_error = str(e)[:50]

                    # 如果不是最后一次重试，稍微等待一下
                    if retry < max_retries - 1:
                        time.sleep(0.2)

            return False, None, last_error

        def process_node(item):
            """处理单个节点的测试"""
            nonlocal tested, valid
            name, (hash_id, node) = item

            is_valid, delay, error = test_single_node(name, hash_id, node)

            with test_lock:
                tested += 1
                if is_valid:
                    valid += 1
                    valid_nodes[hash_id] = node
                    print(f"[{tested}/{total}] ✓ {name[:40]} - {delay}ms", flush=True)
                else:
                    error_key = error if error else "未知错误"
                    error_stats[error_key] = error_stats.get(error_key, 0) + 1
                    print(f"[{tested}/{total}] ✗ {name[:40]} - {error}", flush=True)

        # 使用线程池并发测试
        with ThreadPoolExecutor(max_workers=concurrent_tests) as executor:
            executor.map(process_node, node_names.items())

        print("-" * 60)
        print(f"Clash延迟测试完成！有效节点: {valid}/{total} ({valid*100//total if total > 0 else 0}%)")

        # 输出错误统计
        if error_stats:
            print("\n错误统计:")
            for error, count in sorted(error_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  - {error}: {count}次")

        return valid_nodes

    finally:
        # 清理
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            try:
                process.kill()
            except:
                pass

        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def filter_nodes_by_delay_tcp(nodes_dict: Dict[int, Node], max_delay: float = 1.0, max_workers: int = 50) -> Dict[int, Node]:
    """
    使用TCP连接测试节点延迟（备用方案）
    """
    valid_nodes: Dict[int, Node] = {}
    total = len(nodes_dict)
    tested = 0
    valid = 0

    print(f"开始测试 {total} 个节点的TCP连通性（超时时间: {max_delay}秒）...")

    def test_single_node(item: Tuple[int, Node]) -> Tuple[int, Node, Optional[float]]:
        hash_id, node = item
        delay = test_node_delay(node, timeout=max_delay)
        return hash_id, node, delay

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_single_node, item): item for item in nodes_dict.items()}

        for future in as_completed(futures):
            tested += 1
            try:
                hash_id, node, delay = future.result()

                if delay is not None:
                    valid += 1
                    valid_nodes[hash_id] = node
                    print(f"[{tested}/{total}] ✓ {node.data['name'][:30]} - {int(delay*1000)}ms", flush=True)
                else:
                    print(f"[{tested}/{total}] ✗ {node.data['name'][:30]} - 连接失败", flush=True)
            except Exception as e:
                print(f"[{tested}/{total}] ✗ 测试出错: {e}", flush=True)

    print(f"\nTCP连通性测试完成！有效节点: {valid}/{total}")
    return valid_nodes

def filter_nodes_by_delay(nodes_dict: Dict[int, Node], max_delay: float = 1.0, max_workers: int = 50, use_clash: bool = True, test_urls: Optional[List[str]] = None, concurrent_tests: int = 15) -> Dict[int, Node]:
    """
    测试节点延迟并过滤

    参数:
        nodes_dict: 节点字典
        max_delay: 最大延迟（秒），对于Clash测试会转换为毫秒
        max_workers: TCP测试的并发数
        use_clash: True=使用Clash API测试（推荐），False=使用TCP连接测试
        test_urls: Clash测试使用的URL列表
        concurrent_tests: Clash测试的并发数
    """
    if use_clash:
        return test_nodes_with_clash(nodes_dict, max_delay=int(max_delay*1000), test_urls=test_urls, concurrent_tests=concurrent_tests)
    else:
        return filter_nodes_by_delay_tcp(nodes_dict, max_delay=max_delay, max_workers=max_workers)

def merge_adblock(adblock_name: str, rules: Dict[str, str]) -> None:
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    unblock: Set[str] = set()
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(url)
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] in '!#': continue
            elif line[:2] == '@@':
                unblock.add(line.split('^')[0].strip('@|^'))
            elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                            (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))

    for url in ABFWHITE:
        url = raw2fastly(url)
        try:
            res = session.get(url)
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] == '!': continue
            else: unblock.add(line.split('^')[0].strip('|^'))

    domain_root = DomainTree()
    domain_keys: Set[str] = set()
    for domain in blocked:
        if '/' in domain: continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.','').isdigit(): # IP
            for seg in segs: # '223.73.212.020' is not valid
                if not seg: break
                if seg[0] == '0' and seg != '0': break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)
    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain: break
        else: rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    print(f"共有 {len(rules)} 条规则")

def load_previous_nodes() -> List[str]:
    """
    从之前生成的结果文件中加载节点
    返回节点URL列表
    """
    previous_nodes: List[str] = []

    # 尝试从 list.meta.yml 读取节点
    try:
        print("正在读取之前的节点结果 (list.meta.yml)... ", end='', flush=True)
        with open("list.meta.yml", encoding="utf-8") as f:
            content = f.read()
            # 跳过第一行的时间戳注释
            if content.startswith('#'):
                content = '\n'.join(content.split('\n')[1:])
            config = yaml.full_load(content)
            if config and 'proxies' in config:
                proxies = config['proxies']
                print(f"找到 {len(proxies)} 个节点")
                # 将 Clash 格式的节点转换回 Node 对象
                for proxy in proxies:
                    try:
                        node = Node(proxy)
                        previous_nodes.append(node.url)
                    except Exception as e:
                        # 忽略无法转换的节点
                        pass
                print(f"成功加载 {len(previous_nodes)} 个之前的节点")
            else:
                print("文件为空或格式不正确")
    except FileNotFoundError:
        print("未找到之前的结果文件")
    except Exception as e:
        print(f"读取失败: {e}")
        traceback.print_exc()

    return previous_nodes

# ============================================================
# 源历史记录管理功能
# ============================================================

def load_source_history() -> Dict[str, List[Dict[str, Any]]]:
    """
    加载源历史记录
    返回格式: {url: [{date: "YYYY-MM-DD", success: bool, valid_nodes: int}, ...]}
    """
    if os.path.exists(SOURCE_HISTORY_FILE):
        try:
            with open(SOURCE_HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"加载源历史记录失败: {e}")
    return {}

def save_source_history(history: Dict[str, List[Dict[str, Any]]]) -> None:
    """保存源历史记录"""
    try:
        with open(SOURCE_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except IOError as e:
        print(f"保存源历史记录失败: {e}")

def update_source_history(history: Dict[str, List[Dict[str, Any]]], 
                          url: str, success: bool, valid_nodes: int) -> None:
    """
    更新单个源的历史记录
    只保留最近7天的记录
    """
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    
    if url not in history:
        history[url] = []
    
    # 检查今天是否已有记录，如果有则更新
    for record in history[url]:
        if record['date'] == today:
            # 更新今天的记录（取更好的结果）
            if success and valid_nodes > record['valid_nodes']:
                record['success'] = success
                record['valid_nodes'] = valid_nodes
            return
    
    # 添加今天的记录
    history[url].append({
        'date': today,
        'success': success,
        'valid_nodes': valid_nodes
    })
    
    # 只保留最近7天的记录
    cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=INVALID_DAYS_THRESHOLD)).strftime("%Y-%m-%d")
    history[url] = [r for r in history[url] if r['date'] >= cutoff_date]

def normalize_source_url(line: str) -> Optional[str]:
    """
    从 sources.list 的行中提取规范化的 URL
    返回 None 表示这是注释行或空行
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # 去掉前缀标记
    url = line
    if url.startswith('!'):
        url = url[1:]
    if url.startswith('*'):
        url = url[1:]
    if url.startswith('+'):
        # 动态日期URL，取最后一部分
        parts = url.split()
        url = parts[-1] if parts else url
    
    # 去掉URL参数部分（#后面的）
    if '#' in url:
        url = url.split('#')[0]
    
    return url

def check_source_should_delete(history: Dict[str, List[Dict[str, Any]]], url: str) -> Tuple[bool, str]:
    """
    检查源是否应该被删除
    返回: (是否应删除, 删除原因)
    规则:
    1. 7天内所有访问都失败
    2. 7天内所有获取的代理都无效（valid_nodes=0）
    """
    if url not in history:
        return False, ""
    
    records = history[url]
    
    # 必须有足够的记录（至少7天的数据）
    if len(records) < INVALID_DAYS_THRESHOLD:
        return False, ""
    
    # 检查最近7天的记录
    all_failed = all(not r['success'] for r in records)
    all_no_valid_nodes = all(r['valid_nodes'] == 0 for r in records)
    
    if all_failed:
        return True, f"连续{len(records)}天访问失败"
    if all_no_valid_nodes:
        return True, f"连续{len(records)}天无有效代理"
    
    return False, ""

def cleanup_invalid_sources(history: Dict[str, List[Dict[str, Any]]]) -> List[Tuple[str, str, str]]:
    """
    清理无效的订阅源
    返回被删除的源列表: [(原始行, 规范化URL, 删除原因), ...]
    """
    deleted_sources: List[Tuple[str, str, str]] = []
    
    # 读取 sources.list
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except IOError as e:
        print(f"读取 {SOURCES_FILE} 失败: {e}")
        return deleted_sources
    
    # 检查每一行
    new_lines: List[str] = []
    for line in lines:
        original_line = line.rstrip('\n')
        url = normalize_source_url(original_line)
        
        if url is None:
            # 保留注释和空行
            new_lines.append(line)
            continue
        
        should_delete, reason = check_source_should_delete(history, url)
        if should_delete:
            deleted_sources.append((original_line, url, reason))
            # 不添加到 new_lines，相当于删除
        else:
            new_lines.append(line)
    
    if deleted_sources:
        # 写回 sources.list
        try:
            with open(SOURCES_FILE, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            print(f"已从 {SOURCES_FILE} 删除 {len(deleted_sources)} 个无效源")
        except IOError as e:
            print(f"写入 {SOURCES_FILE} 失败: {e}")
            return []
        
        # 记录到 source_delete.list
        try:
            with open(SOURCE_DELETE_FILE, 'a', encoding='utf-8') as f:
                today = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                for original_line, url, reason in deleted_sources:
                    f.write(f"# [{today}] {reason}\n")
                    f.write(f"{original_line}\n")
            print(f"已将删除记录追加到 {SOURCE_DELETE_FILE}")
        except IOError as e:
            print(f"写入 {SOURCE_DELETE_FILE} 失败: {e}")
        
        # 从历史记录中删除这些源
        for _, url, _ in deleted_sources:
            if url in history:
                del history[url]
        save_source_history(history)
    
    return deleted_sources

def main():
    global exc_queue, merged, FETCH_TIMEOUT, ABFURLS, AUTOURLS, AUTOFETCH
    
    # 加载源历史记录
    source_history = load_source_history()
    print(f"已加载 {len(source_history)} 个源的历史记录")
    
    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if DEBUG_NO_NODES:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        sources = []
    if DEBUG_NO_DYNAMIC:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已选择不抓取动态节点 !!!")
        AUTOURLS = AUTOFETCH = []

    # 加载之前的节点结果
    previous_nodes = load_previous_nodes()
    if previous_nodes:
        print(f"将重新测试 {len(previous_nodes)} 个之前的节点")
        # 将之前的节点添加到源列表中（作为内存中的源）
        # 这样它们会和新采集的节点一起被处理

    print("正在生成动态链接...")
    for auto_fun in AUTOURLS:
        print("正在生成 '"+auto_fun.__name__+"'... ", end='', flush=True)
        try: url = auto_fun()
        except requests.exceptions.RequestException: print("失败！")
        except: print("错误：");traceback.print_exc()
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                print("成功！")
            else: print("跳过！")
    print("正在整理链接...")
    sources_final: Union[Set[str], List[str]] = set()
    airports: Set[str] = set()
    for source in sources:
        if source == 'EOF': break
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    if airports:
        print("正在抓取机场列表...")
        for sub in airports:
            print("合并 '"+sub+"'... ", end='', flush=True)
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                print("正在退出...")
                break
            except requests.exceptions.RequestException:
                print("合并失败！")
            except: traceback.print_exc()
            else:
                if isinstance(res, int):
                    print(res)
                else:
                    for url in res:
                        sources_final.add(url)
                    print("完成！")

    print("正在整理链接...")
    sources_final = list(sources_final)
    sources_final.sort()
    sources_obj = [Source(url) for url in (sources_final + AUTOFETCH)]

    print("开始抓取！")
    threads = [threading.Thread(target=_.get, daemon=True) for _ in sources_obj]
    for thread in threads: thread.start()
    for i in range(len(sources_obj)):
        try:
            for t in range(1, FETCH_TIMEOUT[0]+1):
                print("抓取 '"+sources_obj[i].url+"'... ", end='', flush=True)
                try: threads[i].join(timeout=FETCH_TIMEOUT[1])
                except KeyboardInterrupt:
                    print("正在退出...")
                    FETCH_TIMEOUT = (1, 0)
                    break
                if not threads[i].is_alive(): break
                print(f"{5*t}s")
            if threads[i].is_alive():
                print("超时！")
                continue
            res = sources_obj[i].content
            if isinstance(res, int):
                if res < 0: print("抓取失败！")
                else: print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(sources_obj[i], sourceId=i)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
        except KeyboardInterrupt:
            print("正在退出...")
            break
        while exc_queue:
            print(exc_queue.pop(0), file=sys.stderr, flush=True)

    # 更新源历史记录
    print("\n正在更新源历史记录...")
    for source in sources_obj:
        # 获取规范化的URL（去掉参数等）
        url = source.url
        if '#' in url:
            url = url.split('#')[0]
        
        # 判断抓取是否成功
        success = isinstance(source.content, str) and source.sub is not None
        
        # 统计有效节点数（在merged中的节点）
        valid_nodes = 0
        if source.sub:
            for p in source.sub:
                try:
                    n = Node(p) if isinstance(p, str) else Node(p)
                    if hash(n) in merged:
                        valid_nodes += 1
                except:
                    pass
        
        update_source_history(source_history, url, success, valid_nodes)
    
    # 保存更新后的历史记录
    save_source_history(source_history)
    print(f"已更新 {len(sources_obj)} 个源的历史记录")

    # 合并之前的节点（直接处理，不需要通过Source对象）
    if previous_nodes:
        print(f"\n正在合并之前的 {len(previous_nodes)} 个节点... ", end='', flush=True)
        # 直接遍历之前的节点URL并合并
        previous_count = 0
        for node_url in previous_nodes:
            try:
                n = Node(node_url)
                n.format_name()
                Node.names.add(n.data['name'])
                hashn = hash(n)
                if hashn not in merged:
                    # 只有当节点不存在时才添加（新采集的节点优先）
                    merged[hashn] = n
                    previous_count += 1
                    # 记录这个节点来自"之前的结果"（使用特殊的sourceId=-1）
                    if hashn not in used:
                        used[hashn] = {}
                    used[hashn][-1] = n.name
                # else: 节点已存在（新采集的源中也有这个节点），保留新的，不做任何操作
            except Exception as e:
                # 忽略无法解析的节点
                pass
        print(f"完成！新增 {previous_count} 个之前的节点（去重后）")

    if STOP:
        merged = {}
        for nid, nd in enumerate(STOP_FAKE_NODES.splitlines()):
            merged[nid] = Node(nd)

    # 测试节点延迟并过滤无效节点
    if merged and not STOP:
        print("\n" + "="*60)
        # 只保留延迟小于1000ms的节点
        # 使用多个测试URL和并发测试，提高测试速度和成功率
        filtered = filter_nodes_by_delay(merged, max_delay=1.0, max_workers=50)
        print("="*60)
        
        # 如果测试失败返回 None，使用上次的节点
        if filtered is None:
            print("节点测试失败，将使用上次的有效节点")
            # 只保留之前结果中的节点（sourceId=-1 的节点）
            previous_only = {}
            for hashp, node in merged.items():
                if hashp in used and -1 in used[hashp]:
                    previous_only[hashp] = node
            if previous_only:
                print(f"保留 {len(previous_only)} 个上次的节点")
                merged = previous_only
            else:
                print("警告：没有找到上次的节点，将保留所有节点")
        else:
            merged = filtered

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    for hashp, p in merged.items():
        try:
            if hashp in used:
                # 注意：这一步也会影响到下方的 Clash 订阅，不用再执行一遍！
                p.data['name'] = ','.join([str(_) for _ in sorted(list(used[hash(p)]))])+'|'+p.data['name']
            if p.supports_ray():
                try:
                    txt += p.url + '\n'
                except UnsupportedType as e:
                    print(f"不支持的类型：{e}")
            else: unsupports += 1
        except: traceback.print_exc()
    for p in unknown:
        txt += p+'\n'
    print(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共",
            len(merged)+len(unknown),f"个。{unsupports} 个节点不被 V2Ray 支持。")

    with open("list_raw.txt", 'w', encoding="utf-8") as f:
        f.write(txt)
    with open("list.txt", 'w', encoding="utf-8") as f:
        f.write(b64encodes(txt))
    print("写出完成！")

    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)
    
    rules: Dict[str, str] = {}
    if DEBUG_NO_ADBLOCK:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
    else:
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)

    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    ctg_nodes_meta: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}
    try:
        with open("snippets/_config.yml", encoding="utf-8") as f:
            snip_conf = yaml.full_load(f)
    except (OSError, yaml.error.YAMLError):
        print("片段配置读取失败：")
        traceback.print_exc()
    else:
        print("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories:
            ctg_nodes[ctg] = []
            ctg_nodes_meta[ctg] = []
        for node in merged.values():
            if node.supports_meta():
                ctgs: List[str] = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    if node.supports_clash():
                        ctg_nodes[ctgs[0]].append(node.clash_data)
                    ctg_nodes_meta[ctgs[0]].append(node.clash_data)
        for ctg, proxies in ctg_nodes.items():
            with open("snippets/nodes_"+ctg+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)
        for ctg, proxies in ctg_nodes_meta.items():
            with open("snippets/nodes_"+ctg+".meta.yml", 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)

    print("正在写出 Clash & Meta 订阅...")
    keywords: List[str] = []
    suffixes: List[str] = []
    match_rule = None
    for rule in conf['rules']:
        rule: str
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == 'DOMAIN-KEYWORD':
                keywords.append(rargument)
            elif rtype == 'DOMAIN-SUFFIX':
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ','+rresolve
        else: print("规则 '"+rule+"' 无法被解析！"); continue
        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                print(rargument, "已被 KEYWORD", kwd, "命中")
                break
        else:
            for sfx in suffixes:
                if ('.'+rargument).endswith('.'+sfx) and sfx != rargument:
                    print(rargument, "已被 SUFFIX", sfx, "命中")
                    break
            else:
                k = rtype+','+rargument
                if k not in rules:
                    rules[k] = rpolicy
    conf['rules'] = [','.join(_) for _ in rules.items()]+[match_rule]

    # Clash & Meta
    global_fp: Optional[str] = conf.get('global-client-fingerprint', None)
    proxies: List[Node.DATA_TYPE] = []
    proxies_meta: List[Node.DATA_TYPE] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash: Union[Set[str], List[str]] = set()
    names_clash_meta: Union[Set[str], List[str]] = set()
    for p in merged.values():
        if p.supports_meta():
            if ('client-fingerprint' in p.data and
                    p.data['client-fingerprint'] == global_fp):
                del p.data['client-fingerprint']
            proxies_meta.append(p.clash_data)
            names_clash_meta.add(p.data['name'])
            if p.supports_clash():
                proxies.append(p.clash_data)
                names_clash.add(p.data['name'])
    names_clash = list(names_clash)
    names_clash_meta = list(names_clash_meta)
    conf_meta = copy.deepcopy(conf)

    # Clash
    conf['proxies'] = proxies
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload: disp['proxies'] = ['REJECT']
                else: disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    try:
        dns_mode: Optional[str] = conf['dns']['enhanced-mode']
    except:
        dns_mode: Optional[str] = None
    else:
        conf['dns']['enhanced-mode'] = 'fake-ip'
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))
    with open("snippets/nodes.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies}, allow_unicode=True).replace('!!str ',''))

    # Meta
    conf = conf_meta
    conf['proxies'] = proxies_meta
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash_meta
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes_meta.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload: disp['proxies'] = ['REJECT']
                else: disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    if dns_mode:
        conf['dns']['enhanced-mode'] = dns_mode
    with open("list.meta.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))
    with open("snippets/nodes.meta.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies_meta}, allow_unicode=True).replace('!!str ',''))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values(): snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy: rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/"+name+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: out += f"{len(source.sub)}"
        except: out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    open("list_result.csv",'w').write(out)

    # 清理无效的订阅源（连续7天失败或无有效代理）
    print("\n正在检查无效订阅源...")
    deleted = cleanup_invalid_sources(source_history)
    if deleted:
        print(f"已清理 {len(deleted)} 个无效订阅源：")
        for original_line, url, reason in deleted:
            print(f"  - {url[:60]}... ({reason})")
    else:
        print("没有需要清理的无效订阅源")

    print("\n写出完成！")

if __name__ == '__main__':
    from dynamic import AUTOURLS, AUTOFETCH # type: ignore
    main()
