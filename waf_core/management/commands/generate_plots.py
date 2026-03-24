import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count

logger = logging.getLogger('ml_engine')

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
PLOTS_DIR = BASE_DIR / 'static' / 'analytics'
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

DARK = '#0f1117'; CARD = '#161b27'; GRID = '#1e2738'; TEXT = '#94a3b8'
BLUE = '#3b82f6'; RED = '#ef4444'; GREEN = '#22c55e'; YELLOW = '#f59e0b'
ATTACK_COLORS = {'sqli':'#f97316','xss':'#22c55e','path_traversal':'#8b5cf6','rce':'#ec4899','ddos':'#ef4444','ssrf':'#06b6d4','xxe':'#a78bfa'}


def _style(fig, axlist):
    fig.patch.set_facecolor(DARK)
    for ax in (axlist if hasattr(axlist, '__iter__') else [axlist]):
        ax.set_facecolor(CARD); ax.tick_params(colors=TEXT, labelsize=9)
        ax.xaxis.label.set_color(TEXT); ax.yaxis.label.set_color(TEXT)
        ax.title.set_color('#e2e8f0')
        for sp in ax.spines.values(): sp.set_color(GRID)
        ax.grid(True, color=GRID, linewidth=0.5)


def traffic_timeline(hours=24):
    from waf_core.models import HTTPRequest
    now = timezone.now()
    pts = []
    for i in range(hours):
        e = now - timedelta(hours=i); s = now - timedelta(hours=i + 1)
        t = HTTPRequest.objects.filter(timestamp__range=(s, e)).count()
        b = HTTPRequest.objects.filter(timestamp__range=(s, e), is_blocked=True).count()
        pts.append({'hour': s.strftime('%H:00'), 'total': t, 'blocked': b})
    pts.reverse()
    df = pd.DataFrame(pts)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
    _style(fig, [ax1, ax2])
    fig.suptitle('HTTP Трафік (24 год)', color='#e2e8f0', fontsize=13, fontweight='bold')
    x = np.arange(len(pts))
    ax1.fill_between(x, df['total'], alpha=.2, color=BLUE); ax1.plot(x, df['total'], color=BLUE, lw=2, label='Всі')
    ax1.fill_between(x, df['blocked'], alpha=.3, color=RED); ax1.plot(x, df['blocked'], color=RED, lw=2, label='Заблоковані')
    ax1.set_ylabel('Запитів'); ax1.legend(facecolor=CARD, edgecolor=GRID, labelcolor=TEXT, fontsize=9)
    rate = np.where(df['total'] > 0, df['blocked'] / df['total'] * 100, 0)
    ax2.bar(x, rate, color=YELLOW, alpha=.8, width=.7)
    ax2.set_ylabel('% заблокованих'); ax2.set_ylim(0, 100)
    ax2.set_xticks(x[::2]); ax2.set_xticklabels(df['hour'].iloc[::2], rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / 'traffic.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()
    return str(PLOTS_DIR / 'traffic.png')


def attack_dist(days=7):
    from waf_core.models import DetectedAttack
    since = timezone.now() - timedelta(days=days)
    qs = (DetectedAttack.objects.filter(timestamp__gte=since)
          .values('attack_type__code', 'attack_type__name').annotate(count=Count('id')).order_by('-count'))
    if not qs:
        return ''
    labels = [a['attack_type__name'] for a in qs]
    values = [a['count'] for a in qs]
    colors = [ATTACK_COLORS.get(a['attack_type__code'], BLUE) for a in qs]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))
    _style(fig, [ax1, ax2])
    fig.suptitle(f'Розподіл атак ({days} днів)', color='#e2e8f0', fontsize=13, fontweight='bold')
    wedges, texts, autos = ax1.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140, pctdistance=.82, wedgeprops={'edgecolor': DARK, 'linewidth': 2})
    for t in texts: t.set_color(TEXT); t.set_fontsize(9)
    for a in autos: a.set_color('#e2e8f0'); a.set_fontsize(8); a.set_fontweight('bold')
    y = np.arange(len(labels))
    bars = ax2.barh(y, values, color=colors, alpha=.85, height=.6)
    ax2.set_yticks(y); ax2.set_yticklabels(labels, fontsize=9)
    ax2.set_xlabel('Кількість')
    for bar, val in zip(bars, values):
        ax2.text(bar.get_width() + .1, bar.get_y() + bar.get_height() / 2, str(val), va='center', color=TEXT, fontsize=9)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / 'attack_dist.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()
    return str(PLOTS_DIR / 'attack_dist.png')


class Command(BaseCommand):
    help = 'Generate analytics plots'

    def handle(self, *args, **options):
        self.stdout.write('Generating analytics plots...')
        for name, fn in [('traffic', traffic_timeline), ('attack_dist', attack_dist)]:
            try:
                p = fn()
                self.stdout.write(self.style.SUCCESS(f'  OK: {name} → {p}') if p else self.style.WARNING(f'  SKIP: {name} (no data)'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  FAIL: {name}: {e}'))
        self.stdout.write(self.style.SUCCESS('Done.'))
