import re
import math
import numpy as np
from urllib.parse import unquote, parse_qs

RE_SQLI = re.compile(
    r"(\b(?:select|insert|update|delete|drop|union|exec|execute|cast|convert|"
    r"sleep|benchmark|waitfor|load_file|outfile|dumpfile|information_schema|"
    r"syscolumns|sysobjects|xp_cmdshell|sp_executesql)\b"
    r"|'[^']*'|\"[^\"]*\"|--[^\n]*|/\*.*?\*/|0x[0-9a-fA-F]+"
    r"|\bOR\s+['\"0-9]|AND\s+['\"0-9]|\bOR\b\s+\d+=\d+"
    r"|\bunion\s+(?:all\s+)?select\b"
    r"|;\s*(?:drop|delete|insert|update|select)\b)",
    re.IGNORECASE | re.DOTALL,
)

RE_XSS = re.compile(
    r"(<\s*script[\s>]|</\s*script\s*>"
    r"|javascript\s*:|vbscript\s*:"
    r"|on(?:load|click|error|mouseover|focus|blur|change|submit|keyup|keydown|input)\s*="
    r"|<\s*(?:iframe|object|embed|link|meta|svg|math|img)\s[^>]*(?:src|href|data|xlink:href)\s*=\s*[\"']?\s*(?:javascript|vbscript|data:text/html)"
    r"|expression\s*\("
    r"|document\.(?:cookie|write|location|domain)"
    r"|window\.(?:location|open|eval)"
    r"|\beval\s*\("
    r"|String\.fromCharCode\s*\("
    r"|<\s*img\s[^>]*onerror)",
    re.IGNORECASE | re.DOTALL,
)

RE_PATH = re.compile(
    r"(\.\./|\.\.\\|%2e%2e(?:%2f|%5c|/|\\)|%252e%252e"
    r"|(?:^|/)(?:etc/(?:passwd|shadow|hosts|group|issue)|proc/self/environ"
    r"|windows/(?:system32|win\.ini|boot\.ini)|boot\.ini"
    r"|var/(?:log|www)|usr/(?:local|bin|sbin))"
    r"|/\.\./|\\\.\.\\)",
    re.IGNORECASE,
)

RE_RCE = re.compile(
    r"(;\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|python|perl|php|ruby|nmap|ping)\b"
    r"|\|\s*(?:ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc)\b"
    r"|&&\s*(?:ls|cat|id|whoami|uname|wget|curl|bash|sh)\b"
    r"|\$\([^)]+\)"
    r"|`[^`]+`"
    r"|%0[aAdD]"
    r"|\b(?:system|passthru|shell_exec|proc_open|popen|exec|eval)\s*\("
    r"|<\?php|<%=|{{.*?}}"
    r"|/bin/(?:bash|sh|dash)|cmd\.exe\s*/[cCkK]"
    r"|\bnet\s+(?:user|group|localgroup)\b"
    r"|\bpowershell\b)",
    re.IGNORECASE,
)

RE_SSRF = re.compile(
    r"(https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1"
    r"|169\.254\.169\.254|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|2130706433)"
    r"|file:///"
    r"|dict://|gopher://|ftp://localhost"
    r"|@(?:localhost|127\.)"
    r"|0x7f000001"
    r"|%31%32%37%2e%30%2e%30%2e%31)",
    re.IGNORECASE,
)

RE_XXE = re.compile(
    r"(<!\s*(?:DOCTYPE|ELEMENT|ATTLIST|ENTITY)"
    r"|<!ENTITY\s+\S+\s+SYSTEM"
    r"|SYSTEM\s+[\"'](?:file|http|ftp|expect|php)://"
    r"|%[a-zA-Z_][a-zA-Z0-9_]*;"
    r"|&[a-zA-Z_][a-zA-Z0-9_]*;)",
    re.IGNORECASE,
)

RE_DDOS_UA = re.compile(
    r"(python-requests|go-http-client|curl/|wget/|libwww-perl"
    r"|masscan|zgrab|nikto|nmap|sqlmap|dirbuster|gobuster"
    r"|hydra|medusa|burpsuite|owasp|openvas)",
    re.IGNORECASE,
)

SQLI_EXCLUSIVE_KW = [
    'union select', 'or 1=1', "' or '", '" or "',
    'information_schema', 'xp_cmdshell', 'sp_executesql',
    'waitfor delay', 'benchmark(', 'load_file(',
    'group_concat(', 'extractvalue(', 'updatexml(',
]

XSS_EXCLUSIVE_KW = [
    '<script', 'javascript:', 'onerror=', 'onload=',
    'document.cookie', 'fromcharcode', 'window.location',
    '<iframe', '<svg/onload', 'alert(', 'prompt(', 'confirm(',
]

PATH_EXCLUSIVE_KW = [
    '../', '..\\', 'etc/passwd', 'etc/shadow',
    'win.ini', 'boot.ini', 'system32', '%2e%2e',
]

RCE_EXCLUSIVE_KW = [
    '; ls', '| cat', '`id`', '$(whoami)', '&& uname',
    '/bin/bash', '/bin/sh', 'cmd.exe', 'powershell',
    'wget http', 'curl http', '; cat /etc',
]

SSRF_EXCLUSIVE_KW = [
    '169.254.169.254', 'localhost:',
    'file:///', 'dict://', 'gopher://',
    '127.0.0.1', '0.0.0.0',
]

XXE_EXCLUSIVE_KW = [
    '<!entity', '<!doctype', 'system "file',
    'system "http', '%file;', '%send;', '&xxe;',
]

FEATURE_NAMES = [
    'path_len', 'query_len', 'body_len', 'ua_len',
    'is_post', 'is_get', 'is_put', 'is_delete',
    'url_squote', 'url_dquote', 'url_semi', 'url_dash',
    'url_slash', 'url_angle', 'url_paren', 'url_pct', 'url_null',
    'body_squote', 'body_dquote', 'body_semi', 'body_angle', 'body_paren', 'body_pct',
    'sqli_exclusive_kw', 'sqli_re_matches',
    'xss_exclusive_kw', 'xss_re_matches',
    'path_exclusive_kw', 'path_re_matches', 'dotdot',
    'rce_exclusive_kw', 'rce_re_matches', 'has_pipe_cmd', 'has_backtick',
    'ssrf_exclusive_kw', 'ssrf_re_matches', 'internal_ip',
    'xxe_exclusive_kw', 'xxe_re_matches', 'has_entity',
    'url_entropy', 'body_entropy', 'query_entropy',
    'path_depth', 'filename_len',
    'bot_ua', 'sqlmap_ua', 'scanner_ua', 'empty_ua', 'ddos_ua',
    'ct_json', 'ct_multipart', 'ct_form', 'ct_xml', 'ct_octet',
    'q_eq', 'q_amp', 'q_params',
    'xff', 'xrip', 'high_rps_marker',
    'hex_count', 'pct_double_enc', 'null_byte',
    'xml_tags', 'php_tag', 'template_injection',
]


def _entropy(text):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _specials(text):
    return [
        text.count("'"),
        text.count('"'),
        text.count(';'),
        text.count('-'),
        text.count('/') + text.count('\\'),
        text.count('<') + text.count('>'),
        text.count('(') + text.count(')'),
        text.count('%'),
        text.count('\x00'),
    ]


def extract_features(method, path, query_string, headers, body, client_ip):
    full_url = path + ('?' + query_string if query_string else '')
    decoded_url = unquote(full_url)
    decoded_body = unquote(body)
    combined = (decoded_url + ' ' + decoded_body).lower()
    combined_raw = full_url + ' ' + body

    ua = headers.get('HTTP_USER_AGENT', headers.get('User-Agent', ''))
    ct = headers.get('CONTENT_TYPE', headers.get('Content-Type', ''))
    ua_lower = ua.lower()
    ct_lower = ct.lower()

    us = _specials(full_url)
    bs = _specials(body)

    sqli_ekw = sum(1 for kw in SQLI_EXCLUSIVE_KW if kw in combined)
    xss_ekw = sum(1 for kw in XSS_EXCLUSIVE_KW if kw in combined)
    path_ekw = sum(1 for kw in PATH_EXCLUSIVE_KW if kw in combined)
    rce_ekw = sum(1 for kw in RCE_EXCLUSIVE_KW if kw in combined)
    ssrf_ekw = sum(1 for kw in SSRF_EXCLUSIVE_KW if kw in combined)
    xxe_ekw = sum(1 for kw in XXE_EXCLUSIVE_KW if kw in combined)

    sqli_matches = len(RE_SQLI.findall(combined))
    xss_matches = len(RE_XSS.findall(combined))
    path_matches = len(RE_PATH.findall(combined))
    rce_matches = len(RE_RCE.findall(combined))
    ssrf_matches = len(RE_SSRF.findall(combined))
    xxe_matches = len(RE_XXE.findall(combined))

    has_pipe_cmd = int(bool(re.search(r'\|\s*\w+', combined)))
    has_backtick = int('`' in combined_raw)
    has_entity = int('&' in body and ';' in body and '!' in body)
    internal_ip = int(bool(re.search(
        r'(?:127\.|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)', combined
    )))

    xml_tags = len(re.findall(r'<[a-zA-Z][^>]*>', body))
    php_tag = int('<?php' in combined or '<?=' in combined)
    template_inj = int(bool(re.search(r'\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}', combined)))

    pct_double_enc = int('%25' in full_url)
    null_byte = int('\x00' in combined_raw or '%00' in combined)

    features = [
        len(path),
        len(query_string),
        len(body),
        len(ua),
        int(method == 'POST'),
        int(method == 'GET'),
        int(method == 'PUT'),
        int(method == 'DELETE'),

        us[0], us[1], us[2], us[3], us[4], us[5], us[6], us[7], us[8],
        bs[0], bs[1], bs[2], bs[5], bs[6], bs[7],

        sqli_ekw, sqli_matches,
        xss_ekw, xss_matches,
        path_ekw, path_matches, int('../' in decoded_url or '..\\' in decoded_url),
        rce_ekw, rce_matches, has_pipe_cmd, has_backtick,
        ssrf_ekw, ssrf_matches, internal_ip,
        xxe_ekw, xxe_matches, has_entity,

        _entropy(full_url),
        _entropy(body),
        _entropy(query_string),

        path.count('/'),
        len(path.split('/')[-1]) if '/' in path else len(path),

        int('bot' in ua_lower or 'crawler' in ua_lower),
        int('sqlmap' in ua_lower),
        int('nikto' in ua_lower or 'nmap' in ua_lower or 'scanner' in ua_lower),
        int(not ua),
        int(bool(RE_DDOS_UA.search(ua))),

        int('application/json' in ct_lower),
        int('multipart/form-data' in ct_lower),
        int('application/x-www-form-urlencoded' in ct_lower),
        int('xml' in ct_lower),
        int('octet-stream' in ct_lower),

        query_string.count('='),
        query_string.count('&'),
        len(parse_qs(query_string)),

        int('x-forwarded-for' in str(headers).lower()),
        int('x-real-ip' in str(headers).lower()),
        0,

        combined.count('0x'),
        pct_double_enc,
        null_byte,

        xml_tags,
        php_tag,
        template_inj,
    ]

    return np.array(features, dtype=np.float32)
