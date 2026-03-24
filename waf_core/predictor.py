import logging
import numpy as np
import joblib
from django.conf import settings

logger = logging.getLogger('waf_core')


class MLPredictor:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def load(self):
        if self._loaded:
            return
        self.models = {}
        self.scalers = {}
        models_dir = settings.ML_MODELS_DIR
        for attack_type in settings.WAF_CONFIG['ATTACK_TYPES']:
            mp = models_dir / f'{attack_type}_model.pkl'
            sp = models_dir / f'{attack_type}_scaler.pkl'
            if mp.exists() and sp.exists():
                try:
                    self.models[attack_type] = joblib.load(mp)
                    self.scalers[attack_type] = joblib.load(sp)
                    logger.info(f'Model loaded: {attack_type}')
                except Exception as e:
                    logger.error(f'Failed to load {attack_type}: {e}')
        self._loaded = True

    def predict(self, features: np.ndarray) -> dict:
        self.load()
        X = features.reshape(1, -1)
        results = {}

        sigs = {
            'sqli': X[0, 23] + X[0, 24],
            'xss': X[0, 25] + X[0, 26],
            'path_traversal': X[0, 27] + X[0, 28] + X[0, 29],
            'rce': X[0, 30] + X[0, 31] + X[0, 32] + X[0, 33],
            'ssrf': X[0, 34] + X[0, 35] + X[0, 36],
            'xxe': X[0, 37] + X[0, 38] + X[0, 39],
            'ddos': X[0, 45] + X[0, 46] + X[0, 47] + X[0, 48] + X[0, 49],
        }

        for attack_type, model in self.models.items():
            try:
                Xs = self.scalers[attack_type].transform(X)
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(Xs)[0]
                    score = float(prob[1]) if len(prob) > 1 else float(prob[0])
                else:
                    score = float(model.predict(Xs)[0])

                my_sig = sigs.get(attack_type, 0)
                other_sigs = sum(v for k, v in sigs.items() if k != attack_type)

                if my_sig > 0:
                    score = min(0.99, score + 0.4)

                if my_sig == 0 and other_sigs > 0:
                    score = score * 0.2

                results[attack_type] = score
            except Exception as e:
                logger.error(f'Predict [{attack_type}]: {e}')
                results[attack_type] = 0.0

        return results

    def reload(self):
        self._loaded = False
        self.load()
