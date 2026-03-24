# WAF — Інтелектуальна система фільтрації HTTP-трафіку

**Дипломна робота:** "Інтелектуальна система фільтрації HTTP-трафіку веб-додатків WAF з використанням машинного навчання"

---

## Структура проекту

```
waf/
├── config/
│   ├── settings.py              Django налаштування
│   ├── urls.py
│   └── wsgi.py
│
├── waf_core/                    Ядро WAF
│   ├── models.py                БД: HTTPRequest, DetectedAttack, FirewallException, Alert, IPReputation, MLModelMetrics
│   ├── features.py              Витяг 68 ознак — роздільні паттерни на кожен тип атаки
│   ├── predictor.py             Singleton завантажувач ML-моделей
│   ├── middleware.py            Django middleware (фільтрація кожного запиту)
│   ├── alerts.py                Система алертів + burst detection + email
│   ├── exceptions_cache.py      In-memory кеш винятків з CIDR підтримкою
│   ├── admin.py
│   └── management/commands/
│       ├── train_models.py      Навчання ML-моделей
│       ├── seed_data.py         Початкові типи атак
│       └── generate_plots.py   Аналітичні графіки
│
├── ml_engine/
│   ├── trainer.py               Пайплайн: 6 моделей × 7 типів атак + графіки
│   └── saved_models/            *.pkl моделі та scaler-и
│
├── dashboard/                   Веб-інтерфейс (7 сторінок)
│   ├── views.py
│   ├── urls.py
│   └── templates/dashboard/
│       ├── base.html
│       ├── index.html           Dashboard з алертами
│       ├── requests.html        HTTP запити
│       ├── attacks.html         Виявлені атаки
│       ├── alerts.html          Алерти безпеки
│       ├── exceptions.html      Управління винятками WAF
│       ├── ip.html              IP репутація
│       └── ml.html              ML метрики
│
├── api/                         REST API (DRF)
│   ├── views.py
│   ├── serializers.py
│   └── urls.py
│
├── data_processing/
│   └── loader.py                Завантаження Kaggle + розширені синтетичні датасети
│
├── attack_sim.py                Симулятор атак для тестування WAF
├── manage.py
├── requirements.txt
└── .env.example
```

---

## Типи атак

| Код | Назва | Severity | Датасет |
|-----|-------|----------|---------|
| sqli | SQL Injection | critical | Kaggle + synthetic |
| xss | Cross-Site Scripting | high | Kaggle + synthetic |
| path_traversal | Path Traversal / LFI | high | synthetic |
| rce | Remote Code Execution | critical | synthetic |
| ddos | DDoS / Flood | high | synthetic |
| ssrf | Server-Side Request Forgery | high | synthetic |
| xxe | XML External Entity | high | synthetic |

---

## ML Pipeline

**Для кожного типу атаки** навчається 6 моделей, обирається найкраща за F1-score:

| Модель | Параметри |
|--------|-----------|
| Random Forest | 300 дерев, balanced |
| XGBoost | 300 estimators, lr=0.05 |
| Gradient Boosting | 200 estimators, lr=0.08 |
| MLP Neural Network | 512→256→128→64, adaptive lr |
| SVM | RBF kernel, C=10 |
| Logistic Regression | saga solver, balanced |

**Балансування:** SMOTE (якщо позитивних < 40%)

**Фічі (68 штук):** довжини полів, спецсимволи, ентропія Шеннона, ексклюзивні ключові слова та regex для кожного типу атаки (без перетину).

### Вирішена проблема перехресної класифікації

Стара версія мала спільні ключові слова (`char`, `from`, `where`) для SQLi і XSS.
Нова версія використовує **ексклюзивні паттерни**:
- SQLi: `union select`, `waitfor delay`, `xp_cmdshell`, `extractvalue(`
- XSS: `<script`, `onerror=`, `document.cookie`, `fromcharcode`
- RCE: `; ls`, `| cat`, backticks, `$(...)`, `/bin/bash`
- SSRF: `169.254.169.254`, `file:///`, `gopher://`, internal IP ranges
- XXe: `<!ENTITY`, `SYSTEM "file`, `<!DOCTYPE`

---

## Новий функціонал

### 🛡 Винятки файрволу (`/exceptions/`)
- **IP whitelist/blacklist** — одиночний IP
- **CIDR whitelist/blacklist** — підмережа (10.0.0.0/8)
- **Path whitelist/blacklist** — regex шляху
- **User-Agent whitelist/blacklist** — regex UA
- Термін дії (автоматичне видалення)
- In-memory кеш (без БД запитів на кожен HTTP запит)
- Лічильник спрацювань

### 🔔 Алерти (`/alerts/`)
- Алерт на кожну виявлену атаку
- **Burst detection**: 5+ атак за 5 хвилин → critical alert + email
- Рівні: info / warning / critical
- Статуси: new / acknowledged / resolved
- Email-сповіщення (налаштування через `.env`)
- Кнопки: прочитати, вирішити, заблокувати IP

---

## Встановлення та запуск

### 1. Клонування та залежності

```bash
git clone <url>
cd waf
python -m venv venv
source venv/bin/activate    # Linux/macOS
# або: venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. База даних PostgreSQL

```bash
psql -U postgres -c "CREATE DATABASE waf_db;"
```

### 3. Налаштування

```bash
cp .env .env
# Відредагувати: SECRET_KEY, DB_PASSWORD
# Для email-алертів: EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, ALERT_EMAIL_TO
```

### 4. Ініціалізація

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_data
```

### 5. Навчання моделей

```bash
# Без Kaggle (лише синтетика — швидко, ~5 хв):
python manage.py train_models

# З Kaggle (SQLi + XSS реальні датасети — ~15 хв):
# Спочатку: https://www.kaggle.com/settings → API → Create New Token → ~/.kaggle/kaggle.json
python manage.py train_models --download

# Навчити лише один тип:
python manage.py train_models --attack rce
```

### 6. Запуск

```bash
python manage.py runserver
```

### 7. Аналітичні графіки

```bash
python manage.py generate_plots
```

### 8. Тестування WAF

```bash
# Симулятор атак (поки сервер запущений):
python attack_sim.py --type all --count 10

# Окремий тип:
python attack_sim.py --type sqli --count 20 --delay 0.1
python attack_sim.py --type rce --count 15
python attack_sim.py --type ddos --ddos-rps 50 --ddos-duration 30
```

---

## Dashboard

| URL | Сторінка |
|-----|----------|
| `/` | Головна + нові алерти |
| `/requests/` | HTTP запити |
| `/attacks/` | Виявлені атаки |
| `/alerts/` | Алерти безпеки |
| `/exceptions/` | Управління винятками WAF |
| `/ip-reputation/` | IP репутація |
| `/ml/` | ML моделі та метрики |
| `/admin/` | Django Admin |

---

## REST API

```
GET  /api/v1/requests/                   HTTP запити
GET  /api/v1/attacks/                    Виявлені атаки
GET  /api/v1/exceptions/                 Винятки WAF
POST /api/v1/exceptions/                 Створити виняток
POST /api/v1/exceptions/{id}/toggle/     Вмк/Вимк виняток
POST /api/v1/exceptions/reload_cache/    Перезавантажити кеш
GET  /api/v1/alerts/                     Алерти
GET  /api/v1/alerts/unread_count/        Кількість нових
POST /api/v1/alerts/{id}/acknowledge/    Прочитати алерт
POST /api/v1/alerts/{id}/resolve/        Вирішити алерт
POST /api/v1/alerts/acknowledge_all/     Прочитати всі
GET  /api/v1/ip/                         IP репутація
POST /api/v1/ip/{id}/block/              Заблокувати IP
POST /api/v1/ip/{id}/unblock/            Розблокувати IP
POST /api/v1/ip/{id}/whitelist/          Дозволити IP
GET  /api/v1/ml-models/                  Метрики моделей
GET  /api/v1/ml-models/best/             Найкращі моделі
POST /api/v1/ml-models/retrain/          Перенавчити
GET  /api/v1/stats/                      Загальна статистика
POST /api/v1/analyze/                    Аналіз запиту
```

---

## Конфігурація WAF (`config/settings.py`)

```python
WAF_CONFIG = {
    'ENABLED': True,
    'BLOCK_MODE': True,            # False = тільки логувати
    'ML_THRESHOLD': 0.72,          # Поріг впевненості (0.0–1.0)
    'RATE_LIMIT_REQUESTS': 100,    # Макс запитів
    'RATE_LIMIT_WINDOW': 60,       # Вікно в секундах
    'WHITELIST_IPS': ['127.0.0.1'],
    'EXCLUDED_PATHS': ['/admin/', '/static/', '/login/'],
    'LOG_ALL_REQUESTS': False,
    'ATTACK_TYPES': ['sqli', 'xss', 'path_traversal', 'rce', 'ddos', 'ssrf', 'xxe'],
    'ALERT_ON_ATTACK': True,
    'ALERT_THRESHOLD_COUNT': 5,    # Burst detection
    'ALERT_WINDOW_SECONDS': 300,   # Вікно burst detection
}
```
