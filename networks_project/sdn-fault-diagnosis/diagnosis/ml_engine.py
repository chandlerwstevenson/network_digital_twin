"""
ML-based diagnostic engine using a calibrated ensemble classifier.

Classifies network faults from telemetry feature vectors and uses
per-sample feature analysis + snapshot inspection for fault localization.
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import DiagnosisResult, NetworkSnapshot
from .base import BaseDiagnosticEngine, create_diagnosis, no_fault_result
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).parent.parent / "models" / "rf_fault_classifier.joblib"


class MLEngine(BaseDiagnosticEngine):
    """
    ML-based diagnostic engine using a calibrated scikit-learn pipeline.

    The model is a CalibratedClassifierCV wrapping either a Random Forest
    or Gradient Boosting pipeline (selected automatically during training).
    Probabilities are well-calibrated via Platt scaling.
    """

    def __init__(
        self,
        model_path: Path = None,
        feature_extractor: FeatureExtractor = None,
    ):
        super().__init__(name="ml-random-forest")
        self.feature_extractor = feature_extractor or FeatureExtractor()

        model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        if not model_path.exists():
            raise FileNotFoundError(
                f"No trained model at {model_path}. "
                f"Run 'python -m diagnosis.ml_training' to train one first."
            )

        import joblib
        self.model = joblib.load(model_path)
        self.model_path = model_path
        logger.info(f"ML engine loaded model from {model_path}")

    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None,
    ) -> DiagnosisResult:
        features = self.feature_extractor.extract(snapshot, previous_snapshot)
        features_2d = features.reshape(1, -1)

        proba = self.model.predict_proba(features_2d)[0]
        classes = self.model.classes_

        predicted_idx = np.argmax(proba)
        predicted_class = classes[predicted_idx]
        confidence = float(proba[predicted_idx])

        if predicted_class == "no_fault":
            return no_fault_result(
                reasoning=self._build_reasoning(features, proba, classes, "no_fault")
            )

        location, affected_routers, affected_interfaces = self._locate_fault(
            snapshot, predicted_class, features
        )

        return create_diagnosis(
            fault_class=predicted_class,
            location=location,
            confidence=confidence,
            reasoning=self._build_reasoning(features, proba, classes, predicted_class),
            affected_routers=affected_routers,
            affected_interfaces=affected_interfaces,
            remediation=self._suggest_remediation(predicted_class, location),
        )

    def _locate_fault(
        self,
        snapshot: NetworkSnapshot,
        fault_class: str,
        features: np.ndarray,
    ) -> tuple[str, list[str], list[str]]:
        """
        Locate the fault using per-router feature analysis.

        Uses a scoring approach: for each router, compute an anomaly score
        based on the fault class, then pick the router/interface with the
        highest score.
        """
        affected_routers = []
        affected_interfaces = []
        location = "unknown"

        router_scores: dict[str, tuple[float, str]] = {}

        for rname, t in snapshot.routers.items():
            score = 0.0
            best_iface = "unknown"

            if fault_class == "link_failure":
                for iname, iface in t.interfaces.items():
                    if iface.link_status.lower() == "down":
                        score += 10.0
                        best_iface = iname
                for n in t.non_full_adjacencies:
                    if n.state.lower() == "down":
                        score += 5.0
                        if best_iface == "unknown":
                            best_iface = n.interface
                    else:
                        score += 2.0
                        if best_iface == "unknown":
                            best_iface = n.interface

            elif fault_class == "flapping_link":
                for n in t.non_full_adjacencies:
                    if n.state.lower() not in ("down",):
                        score += 5.0
                        best_iface = n.interface
                    if n.retransmit_counter > 0:
                        score += 2.0
                for iname, iface in t.interfaces.items():
                    if iface.link_status.lower() == "down":
                        score -= 3.0  # less likely flapping if interface is actually down

            elif fault_class == "counter_anomaly":
                for iname, iface in t.interfaces.items():
                    rate = iface.counters.error_rate + iface.counters.drop_rate
                    if rate > score:
                        score = rate
                        best_iface = iname

            elif fault_class == "stale_route":
                for prefix, routes in t.routing_table.routes.items():
                    for route in routes:
                        if route.protocol == "static" and route.distance < 50:
                            score += 5.0
                            best_iface = prefix

            elif fault_class == "missing_route":
                expected = {
                    "192.168.1.0/24", "192.168.2.0/24",
                    "192.168.3.0/24", "192.168.4.0/24",
                }
                present = set(t.routing_table.routes.keys())
                missing = expected - present
                if missing and rname.startswith("spine"):
                    score += len(missing) * 3.0
                    best_iface = next(iter(missing))
                # Leaf with reduced LSA link count
                for lsa in t.lsdb.router_lsas:
                    if lsa.lsa_id == t.router_id and lsa.link_count < 5:
                        score += 2.0

            if score > 0:
                router_scores[rname] = (score, best_iface)

        if router_scores:
            best_router = max(router_scores, key=lambda k: router_scores[k][0])
            best_score, best_iface = router_scores[best_router]
            location = f"{best_router}:{best_iface}"
            affected_routers = [best_router]
            affected_interfaces = [location]

            # Add secondary affected routers (score > 50% of best)
            for rname, (sc, iface) in router_scores.items():
                if rname != best_router and sc > best_score * 0.5:
                    affected_routers.append(rname)
                    affected_interfaces.append(f"{rname}:{iface}")

        return location, affected_routers, affected_interfaces

    def _build_reasoning(
        self,
        features: np.ndarray,
        proba: np.ndarray,
        classes: np.ndarray,
        predicted_class: str,
    ) -> str:
        sorted_idx = np.argsort(proba)[::-1]
        top3 = [(classes[i], float(proba[i])) for i in sorted_idx[:3]]
        proba_str = ", ".join(f"{cls}={p:.3f}" for cls, p in top3)

        # Feature importances from the underlying model
        feature_names = self.feature_extractor.feature_names()
        try:
            # Navigate CalibratedClassifierCV → Pipeline → classifier
            base_estimator = self.model.estimator
            inner_clf = base_estimator.named_steps["clf"]
            importances = inner_clf.feature_importances_
            top_feat_idx = np.argsort(importances)[::-1][:5]
            feat_str = ", ".join(
                f"{feature_names[i]}={features[i]:.2f}" for i in top_feat_idx
            )
        except (AttributeError, KeyError):
            # Fallback: report features with largest absolute values
            abs_feat = np.abs(features)
            top_feat_idx = np.argsort(abs_feat)[::-1][:5]
            feat_str = ", ".join(
                f"{feature_names[i]}={features[i]:.2f}" for i in top_feat_idx
            )

        return (
            f"ML classifier predicted {predicted_class}. "
            f"Class probabilities: [{proba_str}]. "
            f"Key features: [{feat_str}]."
        )

    def _suggest_remediation(self, fault_class: str, location: str) -> str:
        router = location.split(":")[0] if ":" in location else location
        suggestions = {
            "link_failure": f"Check physical connectivity and bring interface {location} back up",
            "flapping_link": f"Investigate instability on {location}: check cables, transceivers, and peer config",
            "stale_route": f"Remove incorrect static route on {router}: 'no ip route <prefix>'",
            "missing_route": f"Restore OSPF network statement: 'network <prefix> area 0' on affected router",
            "counter_anomaly": f"Investigate packet loss on {location}: check for congestion, QoS, or hardware errors",
        }
        return suggestions.get(fault_class, "Investigate the identified anomaly")

    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats["model_path"] = str(self.model_path)
        stats["classes"] = list(self.model.classes_)
        try:
            base = self.model.estimator
            inner = base.named_steps["clf"]
            stats["model_type"] = type(inner).__name__
            stats["n_estimators"] = inner.n_estimators
        except (AttributeError, KeyError):
            stats["model_type"] = type(self.model).__name__
        return stats
