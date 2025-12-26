from __future__ import annotations

from prometheus_client import Counter, Histogram

# Path normalization (reduce Prometheus label cardinality)
def normalize_path(path: str) -> str:
    """
    Normalize known dynamic paths to low-cardinality templates.

    Note: middleware runs before routing, so we can't reliably depend on route templates
    being present in the request scope.
    """
    if path.startswith("/api/v1/results/"):
        return "/api/v1/results/{job_id}"
    if path.startswith("/api/v1/admin/clear-velocity/"):
        return "/api/v1/admin/clear-velocity/{ip_address}"
    return path

# HTTP metrics
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

HTTP_REQUEST_LATENCY_SECONDS = Histogram(
    "http_request_latency_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

# Risk-engine metrics
SIGNAL_LATENCY_SECONDS = Histogram(
    "risk_signal_latency_seconds",
    "Latency per risk signal (seconds)",
    ["signal"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

DECISIONS_TOTAL = Counter(
    "risk_decisions_total",
    "Total decisions made by the risk engine",
    ["level", "action"],
)

# Cache metrics
CACHE_EVENTS_TOTAL = Counter(
    "cache_events_total",
    "Cache events",
    ["cache", "event"],  # event: hit|miss|error
)

# Background enrichment metrics
ENRICHMENT_JOBS_TOTAL = Counter(
    "enrichment_jobs_total",
    "Background enrichment jobs",
    ["event"],  # event: enqueued|started|succeeded|failed
)


