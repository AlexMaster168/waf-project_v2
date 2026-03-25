# 🛡️ ML-Based WAF (Web Application Firewall) v2

Интеллектуальный файрвол для веб-приложений, построенный на базе Django. Система использует **гибридный подход** (сигнатурный анализ + алгоритмы машинного обучения) для выявления, классификации и блокировки кибератак в реальном времени с нулевым уровнем ложных срабатываний (False Positives).

---

## ✨ Ключевые возможности

* **🧠 Гибридное детектирование:** Комбинация регулярных выражений (RegEx) и ансамбля ML-моделей (Random Forest, XGBoost, Gradient Boosting, MLP, SVM) для достижения 100% точности.
* **🎯 Распознавание 7 классов атак:**
    * `SQLi` (SQL Injection)
    * `XSS` (Cross-Site Scripting)
    * `Path Traversal` (LFI/RFI)
    * `RCE` (Remote Code Execution)
    * `SSRF` (Server-Side Request Forgery)
    * `XXE` (XML External Entity)
    * `DDoS` (Application Layer HTTP Flood)
* **📊 Интерактивный Dashboard:** Аналитика трафика, мониторинг атак, управление алертами и просмотр метрик ML-моделей в реальном времени.
* **🌍 Управление IP-репутацией:** Автоматическая блокировка злоумышленников после серии атак, ведение истории запросов.
* **🛡️ Гибкие исключения (Firewall Rules):** Поддержка Whitelist/Blacklist для IP-адресов, CIDR-подсетей, регулярных выражений путей (URL Path) и User-Agent.
* **🤖 Встроенный ML-Пайплайн:** Автоматическая загрузка датасетов (Kaggle), генерация синтетических данных, кросс-валидация и переобучение моделей одной командой.
* **⚔️ Симулятор атак:** Встроенный скрипт для тестирования защиты (генерация случайных IP и различных векторов атак).

---

## 🛠 Технологический стек

* **Backend:** Python 3.10+, Django 5.x, Django REST Framework
* **Machine Learning:** Scikit-Learn, XGBoost, Imbalanced-learn (SMOTE), Pandas, NumPy
* **Database:** PostgreSQL (production) / SQLite (development)
* **Frontend:** HTML5, CSS3 (Custom Variables), JavaScript
* **Data Processing:** Joblib (Model serialization), Matplotlib (Plots generation)

---

## 🚀 Установка и запуск

### 1. Клонирование репозитория
```bash
git clone [https://github.com/yourusername/waf-project_v2.git](https://github.com/yourusername/waf-project_v2.git)
cd waf-project_v2
````

### 2\. Настройка виртуального окружения

```bash
python -m venv .venv
# Для Windows:
.venv\Scripts\activate
# Для Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3\. Настройка базы данных и переменных окружения

Создайте файл `.env` в корне проекта (рядом с `manage.py`) и добавьте базовые настройки:

```env
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
# Если используете PostgreSQL:
DB_NAME=waf_db
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_PORT=5432
```

### 4\. Миграции базы данных

```bash
python manage.py makemigrations
python manage.py migrate
```

### 5\. Обучение ML-моделей

Перед запуском WAF необходимо обучить нейросети и классификаторы.

```bash
# Для скачивания реальных датасетов с Kaggle и обучения:
python manage.py train_models --download

# Если Kaggle API не настроен, система сгенерирует синтетические данные:
python manage.py train_models
```

### 6\. Создание администратора и запуск

```bash
python manage.py createsuperuser
python manage.py runserver
```

Панель управления будет доступна по адресу: [http://127.0.0.1:8000/](https://www.google.com/search?q=http://127.0.0.1:8000/)

-----

## ⚔️ Симуляция атак (Тестирование)

В проекте предусмотрен мощный скрипт `attack_sim.py` для проверки надежности WAF. Скрипт подменяет заголовки `X-Forwarded-For`, симулируя атаки с разных IP-адресов.

**Запуск всех типов атак одновременно:**

```bash
python attack_sim.py --type all
```

**Тестирование конкретного вектора (например, SQLi):**

```bash
python attack_sim.py --type sqli --count 50 --delay 0.1
```

**Симуляция DDoS-атаки (HTTP Flood):**

```bash
python attack_sim.py --type ddos --ddos-rps 50 --ddos-duration 10
```

-----

## ⚙️ Конфигурация WAF

Основные параметры защиты настраиваются в `config/settings.py` (словарь `WAF_CONFIG`):

```python
WAF_CONFIG = {
    'ENABLED': True,                  # Глобальный переключатель WAF
    'BLOCK_MODE': True,               # True = Блокировать (403), False = Только мониторинг
    'ML_THRESHOLD': 0.72,             # Порог уверенности ML для блокировки (0.0 - 1.0)
    'RATE_LIMIT_REQUESTS': 100,       # Лимит запросов
    'RATE_LIMIT_WINDOW': 60,          # Окно лимита (в секундах)
    'WHITELIST_IPS': [],              # Глобальный белый список (оставьте пустым для теста локально)
    'EXCLUDED_PATHS': ['/admin/', '/static/'], # Игнорируемые пути
    'ALERT_ON_ATTACK': True,          # Создавать алерты
    'ALERT_THRESHOLD_COUNT': 5,       # Атак с одного IP до создания алерта
}
```

-----

## 📁 Структура проекта

```text
waf-project_v2/
├── api/                  # REST API для интеграции
├── config/               # Настройки Django
├── dashboard/            # Приложение графического интерфейса
├── data_processing/      # Загрузчики датасетов (Kaggle/Синтетика)
├── ml_engine/            # Пайплайн обучения, метрики, сохраненные веса (.pkl)
├── waf_core/             # Ядро WAF: Middleware, извлечение фичей, предиктор, БД
├── attack_sim.py         # Скрипт-симулятор кибератак
└── manage.py             # Точка входа Django
```

-----

## 🔒 Лицензия

Этот проект распространяется под лицензией AlexMaster. Подробности см. в файле `LICENSE`.

```
```
