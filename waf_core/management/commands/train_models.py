from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Train WAF ML models for all attack types'

    def add_arguments(self, parser):
        parser.add_argument('--download', action='store_true', help='Download Kaggle datasets first')
        parser.add_argument('--dataset', default='all', help='sqli|xss|all')
        parser.add_argument('--attack', default='all', help='Train specific attack type only')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('WAF ML Training Pipeline v2'))
        self.stdout.write('=' * 55)

        if options['download']:
            self._download(options['dataset'])

        try:
            from ml_engine.trainer import run_pipeline
            if options['attack'] != 'all':
                from ml_engine.trainer import train_one, save_metrics_to_db, DATASETS_DIR
                from data_processing.loader import LOADERS as L, df_to_features
                atype = options['attack']
                if atype not in L:
                    raise CommandError(f'Unknown attack type: {atype}. Available: {list(L.keys())}')
                df = L[atype](DATASETS_DIR)
                X = df_to_features(df)
                y = df['label'].values
                results = train_one(atype, X, y)
                try:
                    save_metrics_to_db(atype, results)
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'DB save: {e}'))
                self._print_results({atype: results})
            else:
                results = run_pipeline()
                self._print_results(results)
        except Exception as e:
            raise CommandError(f'Training failed: {e}')

    def _download(self, key):
        from data_processing.loader import download, KAGGLE_DATASETS
        from django.conf import settings
        keys = list(KAGGLE_DATASETS.keys()) if key == 'all' else [key]
        for k in keys:
            self.stdout.write(f'  Downloading {k}...')
            ok = download(k, settings.DATASETS_DIR / k)
            self.stdout.write(
                self.style.SUCCESS(f'  OK: {k}') if ok else self.style.WARNING(f'  FAIL (will use synthetic): {k}'))

    def _print_results(self, results):
        self.stdout.write('\n' + self.style.SUCCESS('Results:'))
        for atype, models in results.items():
            self.stdout.write(f'\n  {atype.upper()}:')
            best = max(models, key=lambda k: models[k]['m']['f1'])
            for name, res in sorted(models.items(), key=lambda x: -x[1]['m']['f1']):
                m = res['m']
                mark = ' ★' if name == best else ''
                self.stdout.write(
                    f'    {name:28s} F1={m["f1"]:.4f}  AUC={m["auc_roc"]:.4f}'
                    f'  P={m["precision"]:.4f}  R={m["recall"]:.4f}{mark}'
                )
