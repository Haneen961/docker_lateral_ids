"""
ML detector — Random Forest inference over the 12-feature flow vector.

The model is trained offline by ml/train.py and persisted via joblib.
At inference time we load it once and call predict_proba on each
FlowFeatures.vector().
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import joblib
import numpy as np

from .features import FEATURE_NAMES, FlowFeatures

log = logging.getLogger(__name__)


@dataclass
class MLDetection:
    src: str
    label: str
    proba: float
    ts: float


class MLDetector:
    def __init__(
        self,
        model_path: str | Path,
        proba_threshold: float = 0.7,
        cooldown_sec: float = 30.0,
    ):
        self.model_path = Path(model_path)
        self.proba_threshold = proba_threshold
        self.cooldown_sec = cooldown_sec
        self._last_alert: Dict[str, float] = {}
        log.info("Loading RF model from %s", self.model_path)
        bundle = joblib.load(self.model_path)
        self.model = bundle["model"]
        self.classes_ = list(bundle.get("classes", self.model.classes_))
        self.feature_names = bundle.get("feature_names", FEATURE_NAMES)
        if list(self.feature_names) != FEATURE_NAMES:
            log.warning("Model feature order differs from runtime — reordering by name")

    def _cooldown_ok(self, src: str) -> bool:
        last = self._last_alert.get(src, 0.0)
        if time.time() - last < self.cooldown_sec:
            return False
        self._last_alert[src] = time.time()
        return True

    def predict(self, f: FlowFeatures) -> Optional[MLDetection]:
        x = np.array([f.vector()], dtype=float)
        probs = self.model.predict_proba(x)[0]
        # Find probability of any non-BENIGN class
        attack_proba = 0.0
        attack_label = "ATTACK"
        for cls, p in zip(self.classes_, probs):
            if str(cls).upper() != "BENIGN" and p > attack_proba:
                attack_proba = float(p)
                attack_label = str(cls)
        if attack_proba >= self.proba_threshold and self._cooldown_ok(f.src):
            return MLDetection(
                src=f.src,
                label=attack_label,
                proba=attack_proba,
                ts=f.window_end,
            )
        return None
