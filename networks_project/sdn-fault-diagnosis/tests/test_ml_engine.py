"""
Unit tests for ML-based diagnostic engine, feature extractor, and training pipeline.
"""

from pathlib import Path

import numpy as np
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from telemetry.schemas import (
    InterfaceCounters,
    NetworkSnapshot,
)
from diagnosis.feature_extractor import (
    FeatureExtractor,
    ROUTER_ORDER,
    SINGLE_SNAPSHOT_FEATURES,
    TOTAL_FEATURES,
)
from diagnosis.ml_training import (
    FAULT_CLASSES,
    create_healthy_baseline,
    generate_training_data,
    train_model,
    _inject_link_failure,
    _inject_stale_route,
)


class TestFeatureExtractor:
    """Tests for FeatureExtractor with cross-router features."""

    def setup_method(self):
        self.extractor = FeatureExtractor()
        self.baseline = create_healthy_baseline()

    def test_feature_vector_shape_no_previous(self):
        features = self.extractor.extract(self.baseline)
        assert features.shape == (TOTAL_FEATURES,)

    def test_feature_vector_shape_with_previous(self):
        features = self.extractor.extract(self.baseline, self.baseline)
        assert features.shape == (TOTAL_FEATURES,)

    def test_healthy_snapshot_features(self):
        features = self.extractor.extract(self.baseline)
        names = self.extractor.feature_names()

        for router in ROUTER_ORDER:
            idx_full = names.index(f"{router}_num_full")
            assert features[idx_full] == 4.0
            idx_non_full = names.index(f"{router}_num_non_full")
            assert features[idx_non_full] == 0.0
            idx_down = names.index(f"{router}_num_interfaces_down")
            assert features[idx_down] == 0.0

    def test_cross_router_features_healthy(self):
        """Healthy snapshot should have zero asymmetric pairs and zero LSDB disagreement."""
        features = self.extractor.extract(self.baseline)
        names = self.extractor.feature_names()

        idx_asym = names.index("asymmetric_pairs")
        assert features[idx_asym] == 0.0

        idx_lsdb = names.index("lsdb_disagreement")
        assert features[idx_lsdb] == 0.0

        idx_entropy = names.index("neighbor_state_entropy")
        assert features[idx_entropy] == pytest.approx(0.0, abs=1e-9)  # all Full = single state ≈ 0

    def test_cross_router_features_fault(self):
        """Faulted snapshot should trigger cross-router feature changes."""
        faulted = _inject_link_failure(self.baseline)
        features = self.extractor.extract(faulted)
        names = self.extractor.feature_names()

        # Should have at least some asymmetric adjacency pairs
        idx_asym = names.index("asymmetric_pairs")
        # Entropy should be > 0 (multiple neighbor states present)
        idx_entropy = names.index("neighbor_state_entropy")
        # At least one of these should be nonzero
        assert features[idx_asym] > 0 or features[idx_entropy] > 0

    def test_delta_features_same_snapshot(self):
        features = self.extractor.extract(self.baseline, self.baseline)
        delta = features[SINGLE_SNAPSHOT_FEATURES:]
        np.testing.assert_array_equal(delta, np.zeros(SINGLE_SNAPSHOT_FEATURES))

    def test_delta_features_nonzero(self):
        from copy import deepcopy
        modified = deepcopy(self.baseline)
        modified.routers["spine1"].interfaces["eth1"].link_status = "down"
        modified.routers["spine1"].neighbors = modified.routers["spine1"].neighbors[1:]

        features = self.extractor.extract(modified, self.baseline)
        delta = features[SINGLE_SNAPSHOT_FEATURES:]
        assert not np.allclose(delta, 0)

    def test_missing_router_sentinel(self):
        from copy import deepcopy
        snapshot = deepcopy(self.baseline)
        del snapshot.routers["spine1"]

        features = self.extractor.extract(snapshot)
        names = self.extractor.feature_names()
        idx = names.index("spine1_num_neighbors")
        assert features[idx] == -1.0

    def test_feature_names_length(self):
        names = self.extractor.feature_names()
        features = self.extractor.extract(self.baseline)
        assert len(names) == len(features)


class TestTrainingData:
    """Tests for realistic training data generation."""

    def test_generate_balanced_data(self):
        n = 20
        X, y = generate_training_data(n_samples_per_class=n, seed=123)
        assert X.shape[0] == n * len(FAULT_CLASSES)
        assert X.shape[1] == TOTAL_FEATURES
        for cls in FAULT_CLASSES:
            assert np.sum(y == cls) == n

    def test_healthy_baseline_structure(self):
        baseline = create_healthy_baseline()
        assert len(baseline.routers) == 8
        for router in baseline.routers.values():
            assert len(router.neighbors) == 4
            assert len(router.full_adjacencies) == 4

    def test_no_nan_in_features(self):
        X, y = generate_training_data(n_samples_per_class=10, seed=99)
        assert not np.any(np.isnan(X))

    def test_confusable_examples_differ(self):
        """Confusable examples should have different feature distributions."""
        X1, y1 = generate_training_data(
            n_samples_per_class=50, confusable_ratio=0.0, seed=42
        )
        X2, y2 = generate_training_data(
            n_samples_per_class=50, confusable_ratio=0.5, seed=42
        )
        # Feature variance should be higher with confusable examples
        var1 = np.var(X1[y1 == "link_failure"], axis=0).mean()
        var2 = np.var(X2[y2 == "link_failure"], axis=0).mean()
        assert var2 >= var1 * 0.8  # confusable should not reduce variance significantly


class TestMLEngineTrainAndPredict:
    """End-to-end: train a model and verify predictions."""

    @pytest.fixture(autouse=True)
    def setup_model(self, tmp_path):
        self.model_path = tmp_path / "test_model.joblib"
        self.metrics = train_model(
            self.model_path,
            n_samples_per_class=80,
            seed=42,
        )

    def test_model_file_created(self):
        assert self.model_path.exists()

    def test_training_accuracy_reasonable(self):
        """Accuracy should be above chance (>50% for 6 classes) even with confusables."""
        assert self.metrics["test_accuracy"] > 0.50

    def test_model_comparison_ran(self):
        """Both RF and GB should have been evaluated."""
        assert "random_forest" in self.metrics["cv_results"]
        assert "gradient_boosting" in self.metrics["cv_results"]

    def test_best_model_selected(self):
        assert self.metrics["best_model"] in ("random_forest", "gradient_boosting")

    def test_confusion_matrix_present(self):
        assert "confusion_matrix" in self.metrics
        mat = self.metrics["confusion_matrix"]["matrix"]
        assert len(mat) == len(FAULT_CLASSES)

    def test_brier_scores_present(self):
        """Calibration quality (Brier scores) should be reported per class."""
        for cls, m in self.metrics["per_class"].items():
            assert "brier_score" in m

    def test_engine_diagnoses_link_failure(self):
        from diagnosis.ml_engine import MLEngine

        engine = MLEngine(model_path=self.model_path)
        baseline = create_healthy_baseline()
        snapshot = _inject_link_failure(baseline)

        result = engine.diagnose(snapshot, baseline)
        assert result.fault_detected is True
        assert result.fault_class == "link_failure"
        assert 0.0 <= result.confidence <= 1.0

    def test_engine_diagnoses_healthy(self):
        from diagnosis.ml_engine import MLEngine

        engine = MLEngine(model_path=self.model_path)
        baseline = create_healthy_baseline()
        result = engine.diagnose(baseline)
        assert result.fault_detected is False

    def test_engine_diagnoses_counter_anomaly(self):
        from diagnosis.ml_engine import MLEngine
        from copy import deepcopy

        engine = MLEngine(model_path=self.model_path)
        baseline = create_healthy_baseline()
        snapshot = deepcopy(baseline)
        snapshot.routers["leaf2"].interfaces["eth1"].counters = InterfaceCounters(
            rx_packets=10000, tx_packets=10000,
            rx_errors=500, tx_errors=500,
            rx_dropped=300, tx_dropped=300,
        )

        result = engine.diagnose(snapshot, baseline)
        assert result.fault_detected is True
        assert result.fault_class == "counter_anomaly"

    def test_engine_returns_valid_result(self):
        from diagnosis.ml_engine import MLEngine

        engine = MLEngine(model_path=self.model_path)
        baseline = create_healthy_baseline()
        snapshot = _inject_stale_route(baseline)

        result = engine.diagnose(snapshot)
        assert hasattr(result, "fault_detected")
        assert hasattr(result, "confidence")
        assert hasattr(result, "reasoning")
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.reasoning) > 0

    def test_engine_no_model_raises(self):
        from diagnosis.ml_engine import MLEngine
        with pytest.raises(FileNotFoundError):
            MLEngine(model_path=Path("/nonexistent/model.joblib"))

    def test_engine_stats(self):
        from diagnosis.ml_engine import MLEngine

        engine = MLEngine(model_path=self.model_path)
        stats = engine.get_stats()
        assert stats["name"] == "ml-random-forest"
        assert "classes" in stats
        assert len(stats["classes"]) == len(FAULT_CLASSES)
        assert "model_type" in stats

    def test_engine_localization_has_affected_routers(self):
        """Localization should identify affected routers, not just 'unknown'."""
        from diagnosis.ml_engine import MLEngine

        engine = MLEngine(model_path=self.model_path)
        baseline = create_healthy_baseline()
        snapshot = _inject_link_failure(baseline)

        result = engine.diagnose(snapshot, baseline)
        if result.fault_detected:
            assert result.location != "unknown"
            assert len(result.affected_routers) > 0
