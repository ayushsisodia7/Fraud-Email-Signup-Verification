from app.core.metrics import normalize_path


def test_normalize_results_path():
    assert normalize_path("/api/v1/results/123") == "/api/v1/results/{job_id}"
    assert normalize_path("/api/v1/results/123-456") == "/api/v1/results/{job_id}"


def test_normalize_admin_clear_velocity_path():
    assert normalize_path("/api/v1/admin/clear-velocity/1.2.3.4") == "/api/v1/admin/clear-velocity/{ip_address}"


def test_normalize_other_paths_unchanged():
    assert normalize_path("/api/v1/analyze") == "/api/v1/analyze"


