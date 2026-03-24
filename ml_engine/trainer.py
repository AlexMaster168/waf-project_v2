import os
import sys
import json
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve,
)
from imblearn.over_sampling import SMOTE
import xgboost as xgb

logger = logging.getLogger('ml_engine')

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / 'ml_engine' / 'saved_models'
DATASETS_DIR = BASE_DIR / 'data_processing' / 'datasets'
PLOTS_DIR = BASE_DIR / 'static' / 'ml_plots'

for d in [MODELS_DIR, PLOTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

DARK = '#0f1117'
CARD = '#161b27'
GRID = '#1e2738'
TEXT = '#94a3b8'
BLUE = '#3b82f6'
RED  = '#ef4444'
GREEN = '#22c55e'
YELLOW = '#f59e0b'
PURPLE = '#8b5cf6'

ATTACK_COLORS = {
    'sqli': '#f97316', 'xss': '#22c55e', 'path_traversal': '#8b5cf6',
    'rce': '#ec4899', 'ddos': '#ef4444', 'ssrf': '#06b6d4', 'xxe': '#a78bfa',
}


def _style(fig, axlist):
    fig.patch.set_facecolor(DARK)
    for ax in (axlist if hasattr(axlist, '__iter__') else [axlist]):
        ax.set_facecolor(CARD)
        ax.tick_params(colors=TEXT, labelsize=9)
        ax.xaxis.label.set_color(TEXT)
        ax.yaxis.label.set_color(TEXT)
        ax.title.set_color('#e2e8f0')
        for sp in ax.spines.values():
            sp.set_color(GRID)
        ax.grid(True, color=GRID, linewidth=0.5)


def build_models():
    return {
        'random_forest': RandomForestClassifier(
            n_estimators=300, max_depth=None, min_samples_split=4,
            min_samples_leaf=1, max_features='sqrt',
            class_weight='balanced', random_state=42, n_jobs=-1,
        ),
        'xgboost': xgb.XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.05,
            subsample=0.85, colsample_bytree=0.85,
            min_child_weight=3, gamma=0.1,
            random_state=42, eval_metric='logloss', verbosity=0,
        ),
        'gradient_boosting': GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.08,
            subsample=0.85, min_samples_split=4, random_state=42,
        ),
        'mlp': MLPClassifier(
            hidden_layer_sizes=(512, 256, 128, 64),
            activation='relu', solver='adam',
            alpha=0.0005, batch_size=128,
            learning_rate='adaptive', max_iter=400, random_state=42,
        ),
        'svm': SVC(
            kernel='rbf', C=10, gamma='scale',
            probability=True, class_weight='balanced',
            random_state=42, max_iter=2000,
        ),
        'logistic_regression': LogisticRegression(
            C=5.0, class_weight='balanced',
            max_iter=2000, random_state=42, solver='saga',
        ),
    }


def _metrics(y_true, y_pred, y_proba):
    return {
        'accuracy':  float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall':    float(recall_score(y_true, y_pred, zero_division=0)),
        'f1':        float(f1_score(y_true, y_pred, zero_division=0)),
        'auc_roc':   float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else 0.0,
    }


def plot_roc_pr(results, attack_type):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    _style(fig, [ax1, ax2])
    fig.suptitle(f'ROC / PR — {attack_type.upper()}', color='#e2e8f0', fontsize=13, fontweight='bold')
    ax1.plot([0, 1], [0, 1], 'k--', alpha=0.4, label='Random')
    ax1.set_title('ROC Curves')
    ax2.set_title('Precision-Recall Curves')
    colors = plt.cm.tab10(np.linspace(0, 1, len(results)))
    for (name, res), c in zip(results.items(), colors):
        fpr, tpr, _ = roc_curve(res['y_true'], res['y_proba'])
        pr, rc, _ = precision_recall_curve(res['y_true'], res['y_proba'])
        ax1.plot(fpr, tpr, color=c, linewidth=1.5, label=f"{name} AUC={res['m']['auc_roc']:.3f}")
        ax2.plot(rc, pr, color=c, linewidth=1.5, label=f"{name} F1={res['m']['f1']:.3f}")
    for ax, xl, yl in [(ax1, 'FPR', 'TPR'), (ax2, 'Recall', 'Precision')]:
        ax.set_xlabel(xl)
        ax.set_ylabel(yl)
        ax.legend(fontsize=7, facecolor=CARD, edgecolor=GRID, labelcolor=TEXT)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / f'{attack_type}_roc_pr.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()


def plot_confusion(results, attack_type):
    names = list(results.keys())
    n = len(names)
    cols = min(3, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
    _style(fig, list(axes.flat) if hasattr(axes, 'flat') else [axes])
    fig.suptitle(f'Confusion Matrices — {attack_type.upper()}', color='#e2e8f0', fontsize=13, fontweight='bold')
    axlist = list(axes.flat) if hasattr(axes, 'flat') else [axes]
    for ax, name in zip(axlist, names):
        res = results[name]
        cm = confusion_matrix(res['y_true'], res['y_pred'])
        ax.imshow(cm, cmap='Blues')
        ax.set_title(name, fontsize=10)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Normal', 'Attack'], fontsize=8)
        ax.set_yticklabels(['Normal', 'Attack'], fontsize=8)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha='center', va='center', fontsize=12,
                        color='white' if cm[i, j] > cm.max() / 2 else 'black')
    for ax in axlist[n:]:
        ax.set_visible(False)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / f'{attack_type}_confusion.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()


def plot_feature_importance(model, attack_type, model_name):
    if not hasattr(model, 'feature_importances_'):
        return
    from waf_core.features import FEATURE_NAMES
    imp = model.feature_importances_
    top_n = min(20, len(imp))
    idx = np.argsort(imp)[::-1][:top_n]
    fig, ax = plt.subplots(figsize=(10, 6))
    _style(fig, [ax])
    ax.set_title(f'Feature Importance — {model_name} ({attack_type})', color='#e2e8f0', fontsize=11)
    color = ATTACK_COLORS.get(attack_type, BLUE)
    ax.barh(range(top_n), imp[idx[::-1]], color=color, alpha=0.85)
    fn = FEATURE_NAMES
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([fn[i] if i < len(fn) else f'f{i}' for i in idx[::-1]], fontsize=8)
    ax.set_xlabel('Importance')
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / f'{attack_type}_{model_name}_features.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()


def plot_all_comparison(all_metrics):
    metric_keys = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc']
    attack_types = list(all_metrics.keys())
    n = len(attack_types)
    fig, axes = plt.subplots(n, 1, figsize=(13, 5 * n))
    if n == 1:
        axes = [axes]
    _style(fig, axes)
    fig.suptitle('Порівняння моделей по всіх типах атак', color='#e2e8f0', fontsize=14, fontweight='bold')
    palette = [BLUE, RED, GREEN, YELLOW, PURPLE, '#06b6d4']
    for ax, atype in zip(axes, attack_types):
        model_names = list(all_metrics[atype].keys())
        x = np.arange(len(model_names))
        w = 0.14
        for i, (mk, c) in enumerate(zip(metric_keys, palette)):
            vals = [all_metrics[atype][mn].get(mk, 0) for mn in model_names]
            ax.bar(x + i * w, vals, w, label=mk.upper(), color=c, alpha=0.85)
        ax.set_title(f'{atype.upper()}', color='#e2e8f0', fontsize=11)
        ax.set_xticks(x + w * 2)
        ax.set_xticklabels(model_names, rotation=20, ha='right', fontsize=9)
        ax.set_ylim(0, 1.12)
        ax.set_ylabel('Score')
        ax.legend(fontsize=8, facecolor=CARD, edgecolor=GRID, labelcolor=TEXT, loc='lower right')
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / 'comparison.png', dpi=150, bbox_inches='tight', facecolor=DARK)
    plt.close()


def train_one(attack_type, X, y):
    logger.info(f'[{attack_type}] Samples={len(X)}, Positives={y.sum()}, Negatives={len(y)-y.sum()}')

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = RobustScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    k = min(5, int(y_tr.sum()) - 1)
    if k >= 1 and y_tr.sum() < len(y_tr) * 0.4:
        try:
            sm = SMOTE(random_state=42, k_neighbors=k)
            X_tr_s, y_tr = sm.fit_resample(X_tr_s, y_tr)
            logger.info(f'[{attack_type}] After SMOTE: {len(X_tr_s)}')
        except Exception as e:
            logger.warning(f'[{attack_type}] SMOTE skipped: {e}')

    results = {}
    best_f1, best_name, best_model = -1, None, None

    for name, model in build_models().items():
        try:
            model.fit(X_tr_s, y_tr)
            y_pred = model.predict(X_te_s)
            y_prob = (model.predict_proba(X_te_s)[:, 1]
                      if hasattr(model, 'predict_proba') else y_pred.astype(float))
            m = _metrics(y_te, y_pred, y_prob)
            results[name] = {'m': m, 'y_true': y_te, 'y_pred': y_pred, 'y_proba': y_prob, 'model': model}
            logger.info(f'  [{attack_type}] {name}: F1={m["f1"]:.4f} AUC={m["auc_roc"]:.4f} P={m["precision"]:.4f} R={m["recall"]:.4f}')
            if m['f1'] > best_f1:
                best_f1, best_name, best_model = m['f1'], name, model
        except Exception as e:
            logger.error(f'  [{attack_type}] {name} FAILED: {e}')

    if best_model:
        joblib.dump(best_model, MODELS_DIR / f'{attack_type}_model.pkl')
        joblib.dump(scaler, MODELS_DIR / f'{attack_type}_scaler.pkl')
        meta = {
            'attack_type': attack_type,
            'best_model': best_name,
            'best_f1': best_f1,
            'metrics': results[best_name]['m'],
            'all': {k: v['m'] for k, v in results.items()},
        }
        with open(MODELS_DIR / f'{attack_type}_meta.json', 'w') as f:
            json.dump(meta, f, indent=2)
        logger.info(f'[{attack_type}] BEST: {best_name} F1={best_f1:.4f}')

    return results


def save_metrics_to_db(attack_type, results):
    try:
        import django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
        django.setup()
    except RuntimeError:
        pass
    from waf_core.models import MLModelMetrics
    from waf_core.features import FEATURE_NAMES

    best_name = max(results, key=lambda k: results[k]['m']['f1'])
    for name, res in results.items():
        m = res['m']
        cm = confusion_matrix(res['y_true'], res['y_pred']).tolist()
        fi = {}
        if hasattr(res['model'], 'feature_importances_'):
            imp = res['model'].feature_importances_
            fi = {(FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f'f{i}'): float(v)
                  for i, v in enumerate(imp)}
        MLModelMetrics.objects.update_or_create(
            model_name=name, version='2.0', attack_type=attack_type,
            defaults={
                'accuracy': m['accuracy'], 'precision': m['precision'],
                'recall': m['recall'], 'f1_score': m['f1'], 'auc_roc': m['auc_roc'],
                'training_samples': 0, 'test_samples': len(res['y_true']),
                'is_active': (name == best_name),
                'model_path': str(MODELS_DIR / f'{attack_type}_model.pkl'),
                'confusion_matrix': {'matrix': cm},
                'feature_importance': fi,
                'hyperparameters': {},
            },
        )


def run_pipeline():
    from data_processing.loader import LOADERS, df_to_features

    logger.info('=' * 60)
    logger.info('WAF ML Training Pipeline v2 started')
    logger.info('=' * 60)

    all_results = {}
    all_metrics = {}

    for attack_type, loader_fn in LOADERS.items():
        try:
            df = loader_fn(DATASETS_DIR)
            logger.info(f'[{attack_type}] Loaded {len(df)} rows, positives={df["label"].sum()}')
            X = df_to_features(df)
            y = df['label'].values.astype(int)

            if y.sum() == 0 or (len(y) - y.sum()) == 0:
                logger.warning(f'[{attack_type}] Skipping — all one class')
                continue

            results = train_one(attack_type, X, y)
            all_results[attack_type] = results

            plot_roc_pr(results, attack_type)
            plot_confusion(results, attack_type)

            best_name = max(results, key=lambda k: results[k]['m']['f1'])
            plot_feature_importance(results[best_name]['model'], attack_type, best_name)

            all_metrics[attack_type] = {k: v['m'] for k, v in results.items()}

            try:
                save_metrics_to_db(attack_type, results)
            except Exception as e:
                logger.warning(f'[{attack_type}] DB save failed: {e}')

        except Exception as e:
            logger.error(f'[{attack_type}] Pipeline error: {e}', exc_info=True)

    if all_metrics:
        plot_all_comparison(all_metrics)

    logger.info('=' * 60)
    logger.info('Training complete')
    logger.info('=' * 60)
    return all_results


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(asctime)s %(message)s')
    sys.path.insert(0, str(BASE_DIR))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    import django
    django.setup()
    run_pipeline()
