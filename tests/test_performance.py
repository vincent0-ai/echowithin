"""
EchoWithin CI Performance Benchmark Test
=========================================
Tests internal application response latency against key routes using the test client.
Outputs an SLA benchmark table to stdout and asserts p95 latency stays under budget.
"""
import time
import statistics
import pytest

LATENCY_BUDGET_MS = 800  # p95 SLA budget in milliseconds

PUBLIC_ROUTES = [
    ("Home", "/"),
    ("About", "/about"),
    ("FAQ", "/faq"),
    ("Login Page", "/login"),
    ("Feed XML", "/feed.xml"),
]

AUTH_ROUTES = [
    ("Dashboard", "/dashboard"),
    ("Personal Space", "/personal_space"),
    ("Messages", "/messages"),
    ("Communities", "/communities"),
    ("API: Unread Count", "/api/messages/unread_count"),
    ("API: Badge Counts", "/api/notifications/badge-counts"),
    ("API: Activity Feed", "/api/activity/feed"),
    ("API: My Notes", "/api/v1/notes"),
]


def _benchmark_routes(client, routes, req_type):
    failed_routes = []

    print(f"\n--- Benchmark: {req_type} Routes ---")
    print(f"{'Route':<25} {'Avg (ms)':<10} {'P95 (ms)':<10} {'Budget':<10} {'Verdict'}")
    print("-" * 70)

    for name, path in routes:
        timings = []

        # 1 warm-up request
        try:
            client.get(path, follow_redirects=False)
        except Exception:
            pass

        # 5 measurement samples
        for _ in range(5):
            start = time.perf_counter()
            client.get(path, follow_redirects=False)
            elapsed_ms = (time.perf_counter() - start) * 1000
            timings.append(elapsed_ms)

        avg_ms = round(statistics.mean(timings), 1)
        sorted_t = sorted(timings)
        p95_ms = round(sorted_t[int(len(sorted_t) * 0.95)] if len(sorted_t) > 1 else sorted_t[0], 1)

        if p95_ms <= 200:
            verdict_display = "Fast"
        elif p95_ms <= LATENCY_BUDGET_MS:
            verdict_display = "Moderate"
        else:
            verdict_display = "Exceeded"
            failed_routes.append((name, path, p95_ms))

        budget_str = f"<{LATENCY_BUDGET_MS}ms"
        print(f"{name:<25} {avg_ms:<10.1f} {p95_ms:<10.1f} {budget_str:<10} {verdict_display}")

    return failed_routes


def test_public_routes_latency(https_client):
    """Measures public routes latency and ensures SLA budget is met."""
    failed = _benchmark_routes(https_client, PUBLIC_ROUTES, "Public")
    assert not failed, f"Public routes exceeded {LATENCY_BUDGET_MS}ms budget: {failed}"


def test_authenticated_routes_latency(auth_client):
    """Measures authenticated routes latency and ensures SLA budget is met."""
    with auth_client.session_transaction() as sess:
        sess['ew_session_token'] = 'ci-perf-token'
    failed = _benchmark_routes(auth_client, AUTH_ROUTES, "Authenticated")
    assert not failed, f"Authenticated routes exceeded {LATENCY_BUDGET_MS}ms budget: {failed}"