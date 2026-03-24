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
        for attack_type, model in self.models.items():
            try:
                Xs = self.scalers[attack_type].transform(X)
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(Xs)[0]
                    score = float(prob[1]) if len(prob) > 1 else float(prob[0])
                else:
                    score = float(model.predict(Xs)[0])
                results[attack_type] = score
            except Exception as e:
                logger.error(f'Predict [{attack_type}]: {e}')
                results[attack_type] = 0.0
        return results

    def reload(self):
        self._loaded = False
        self.load()
