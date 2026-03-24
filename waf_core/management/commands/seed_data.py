from django.core.management.base import BaseCommand
from waf_core.models import AttackType

TYPES = [
    {'code': 'sqli', 'name': 'SQL Injection', 'severity': 'critical',
     'description': 'Впровадження SQL-коду для маніпуляцій з базою даних. Може призвести до витоку або знищення даних.',
     'cve_references': ['CWE-89']},
    {'code': 'xss', 'name': 'Cross-Site Scripting', 'severity': 'high',
     'description': 'Впровадження JavaScript у сторінки для виконання в браузері жертви. Крадіжка сесій, cookie.',
     'cve_references': ['CWE-79']},
    {'code': 'path_traversal', 'name': 'Path Traversal / LFI', 'severity': 'high',
     'description': 'Обхід директорій через ../ для доступу до файлів поза дозволеною зоною.',
     'cve_references': ['CWE-22']},
    {'code': 'rce', 'name': 'Remote Code Execution', 'severity': 'critical',
     'description': 'Виконання довільних команд ОС на сервері через впровадження в параметри.',
     'cve_references': ['CWE-78', 'CWE-94']},
    {'code': 'ddos', 'name': 'DDoS / Flood', 'severity': 'high',
     'description': 'Масові запити від ботів для перевантаження сервера та відмови в обслуговуванні.',
     'cve_references': []},
    {'code': 'ssrf', 'name': 'Server-Side Request Forgery', 'severity': 'high',
     'description': 'Примусове надсилання запитів з сервера до внутрішніх ресурсів (metadata, localhost).',
     'cve_references': ['CWE-918']},
    {'code': 'xxe', 'name': 'XML External Entity', 'severity': 'high',
     'description': 'Впровадження зовнішніх сутностей XML для читання файлів або SSRF.',
     'cve_references': ['CWE-611']},
    {'code': 'csrf', 'name': 'Cross-Site Request Forgery', 'severity': 'medium',
     'description': 'Підробка запитів від імені автентифікованого користувача.',
     'cve_references': ['CWE-352']},
]


class Command(BaseCommand):
    help = 'Seed initial attack types into the database'

    def handle(self, *args, **options):
        self.stdout.write('Seeding attack types...')
        for data in TYPES:
            obj, created = AttackType.objects.update_or_create(code=data['code'], defaults=data)
            action = 'Created' if created else 'Updated'
            self.stdout.write(self.style.SUCCESS(f'  {action}: {data["code"]} ({data["severity"]})'))
        self.stdout.write(self.style.SUCCESS(f'\nDone. Total: {AttackType.objects.count()} types.'))
