import ipaddress
import re
import logging
from django.utils import timezone

logger = logging.getLogger('waf_core')

_cache = {
    'ip_whitelist': set(),
    'ip_blacklist': set(),
    'path_whitelist': [],
    'path_blacklist': [],
    'ua_whitelist': [],
    'ua_blacklist': [],
    'cidr_whitelist': [],
    'cidr_blacklist': [],
    'loaded': False,
}


def reload():
    from .models import FirewallException
    now = timezone.now()
    for key in _cache:
        if key != 'loaded':
            if isinstance(_cache[key], set):
                _cache[key] = set()
            else:
                _cache[key] = []

    for exc in FirewallException.objects.filter(is_active=True):
        if exc.expires_at and now > exc.expires_at:
            continue
        t = exc.exception_type
        v = exc.value.strip()
        if t in ('ip_whitelist', 'ip_blacklist'):
            _cache[t].add(v)
        elif t in ('path_whitelist', 'path_blacklist', 'ua_whitelist', 'ua_blacklist'):
            try:
                _cache[t].append(re.compile(v, re.IGNORECASE))
            except re.error:
                _cache[t].append(re.compile(re.escape(v), re.IGNORECASE))
        elif t in ('cidr_whitelist', 'cidr_blacklist'):
            try:
                _cache[t].append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                logger.warning(f'Invalid CIDR: {v}')

    _cache['loaded'] = True
    logger.info('Firewall exceptions cache reloaded')


def _ensure_loaded():
    if not _cache['loaded']:
        reload()


def _ip_in_networks(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def _matches_patterns(value, patterns):
    return any(p.search(value) for p in patterns)


def is_ip_whitelisted(ip):
    _ensure_loaded()
    return ip in _cache['ip_whitelist'] or _ip_in_networks(ip, _cache['cidr_whitelist'])


def is_ip_blacklisted(ip):
    _ensure_loaded()
    return ip in _cache['ip_blacklist'] or _ip_in_networks(ip, _cache['cidr_blacklist'])


def is_path_whitelisted(path):
    _ensure_loaded()
    return _matches_patterns(path, _cache['path_whitelist'])


def is_path_blacklisted(path):
    _ensure_loaded()
    return _matches_patterns(path, _cache['path_blacklist'])


def is_ua_whitelisted(ua):
    _ensure_loaded()
    return _matches_patterns(ua, _cache['ua_whitelist'])


def is_ua_blacklisted(ua):
    _ensure_loaded()
    return _matches_patterns(ua, _cache['ua_blacklist'])


def increment_hit(exception_type, value):
    from .models import FirewallException
    try:
        FirewallException.objects.filter(
            exception_type=exception_type, value=value, is_active=True
        ).update(hit_count=models.F('hit_count') + 1)
    except Exception:
        pass
