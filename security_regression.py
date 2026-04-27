#!/usr/bin/env python3
"""Security regression runner for queue/ticketing/payment flows.

This script is defensive: it validates that security controls are enforced.
It does NOT attempt to bypass systems; it verifies expected rejections.

Checks implemented:
- Rejection of tampered tokens
- Anti-replay for one-time checkout grants
- Rate limiting behavior
- Payment idempotency behavior
- Session/device mismatch rejection
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class ApiResponse:
    status: int
    body: Dict[str, Any]
    raw: str


class HttpClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> ApiResponse:
        url = f"{self.base_url}{path}"
        data = None
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return ApiResponse(resp.status, _decode_json(raw), raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            return ApiResponse(exc.code, _decode_json(raw), raw)


def _decode_json(raw: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"_value": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw}


class CheckFailure(Exception):
    pass


@dataclass
class CheckResult:
    name: str
    ok: bool
    details: str


class SecurityRegression:
    def __init__(self, client: HttpClient, cfg: argparse.Namespace):
        self.client = client
        self.cfg = cfg

    def run(self) -> int:
        checks = [
            self.check_tampered_token,
            self.check_anti_replay,
            self.check_rate_limit,
            self.check_idempotency,
            self.check_session_device_mismatch,
        ]
        results: list[CheckResult] = []

        for check in checks:
            try:
                detail = check()
                results.append(CheckResult(check.__name__, True, detail))
            except CheckFailure as exc:
                results.append(CheckResult(check.__name__, False, str(exc)))
            except Exception as exc:  # pragma: no cover
                results.append(CheckResult(check.__name__, False, f"Unexpected error: {exc}"))

        failures = [r for r in results if not r.ok]
        print("\n=== Security Regression Summary ===")
        for result in results:
            prefix = "PASS" if result.ok else "FAIL"
            print(f"[{prefix}] {result.name}: {result.details}")

        print(f"\nTotal: {len(results)} checks | Failures: {len(failures)}")
        return 1 if failures else 0

    def check_tampered_token(self) -> str:
        token = self.cfg.queue_token
        if not token:
            raise CheckFailure("Missing --queue-token")

        tampered = _tamper_token(token)
        headers = {
            "Authorization": f"Bearer {self.cfg.access_token}",
            self.cfg.queue_header: tampered,
            "X-Session-ID": self.cfg.session_id,
            "X-Device-ID": self.cfg.device_id,
        }
        resp = self.client.request("POST", self.cfg.checkout_start_path, headers=headers, payload={"dry_run": True})
        if resp.status not in self.cfg.reject_statuses:
            raise CheckFailure(f"Expected rejection {self.cfg.reject_statuses}, got {resp.status} ({resp.raw[:180]})")
        return f"Tampered token rejected with status {resp.status}."

    def check_anti_replay(self) -> str:
        grant = self.cfg.checkout_grant
        if not grant:
            raise CheckFailure("Missing --checkout-grant")

        headers = {
            "Authorization": f"Bearer {self.cfg.access_token}",
            self.cfg.grant_header: grant,
            "X-Session-ID": self.cfg.session_id,
            "X-Device-ID": self.cfg.device_id,
        }
        payload = {"event_id": self.cfg.event_id, "ticket_qty": 1}

        first = self.client.request("POST", self.cfg.checkout_finalize_path, headers=headers, payload=payload)
        second = self.client.request("POST", self.cfg.checkout_finalize_path, headers=headers, payload=payload)

        if first.status not in self.cfg.success_statuses:
            raise CheckFailure(f"First use should succeed, got {first.status} ({first.raw[:180]})")
        if second.status not in self.cfg.reject_statuses:
            raise CheckFailure(f"Replay should be rejected, got {second.status} ({second.raw[:180]})")
        return f"One-time grant accepted once ({first.status}) then rejected on replay ({second.status})."

    def check_rate_limit(self) -> str:
        headers = {"Authorization": f"Bearer {self.cfg.access_token}", "X-Session-ID": self.cfg.session_id}
        got_429 = False
        statuses: list[int] = []

        for _ in range(self.cfg.rate_limit_burst):
            resp = self.client.request("GET", self.cfg.rate_limit_probe_path, headers=headers)
            statuses.append(resp.status)
            if resp.status == 429:
                got_429 = True
                break
            time.sleep(self.cfg.rate_limit_interval_ms / 1000)

        if not got_429:
            raise CheckFailure(f"No 429 observed during burst. statuses={statuses}")
        return f"Rate limit triggered with statuses={statuses}."

    def check_idempotency(self) -> str:
        key = str(uuid.uuid4())
        headers = {
            "Authorization": f"Bearer {self.cfg.access_token}",
            "Idempotency-Key": key,
            "X-Session-ID": self.cfg.session_id,
            "X-Device-ID": self.cfg.device_id,
        }
        payload = {"order_id": self.cfg.order_id, "amount": self.cfg.amount, "currency": self.cfg.currency}

        first = self.client.request("POST", self.cfg.payment_confirm_path, headers=headers, payload=payload)
        second = self.client.request("POST", self.cfg.payment_confirm_path, headers=headers, payload=payload)

        if first.status not in self.cfg.success_statuses:
            raise CheckFailure(f"First idempotent call failed unexpectedly: {first.status} ({first.raw[:180]})")
        if second.status not in self.cfg.success_statuses:
            raise CheckFailure(f"Second identical idempotent call should succeed/replay: {second.status} ({second.raw[:180]})")

        first_ref = _stable_result_ref(first.body)
        second_ref = _stable_result_ref(second.body)
        if first_ref and second_ref and first_ref != second_ref:
            raise CheckFailure(f"Idempotency mismatch: first={first_ref}, second={second_ref}")

        return f"Idempotent duplicate requests are stable (status {first.status}/{second.status})."

    def check_session_device_mismatch(self) -> str:
        headers = {
            "Authorization": f"Bearer {self.cfg.access_token}",
            self.cfg.queue_header: self.cfg.queue_token,
            "X-Session-ID": f"{self.cfg.session_id}-mismatch",
            "X-Device-ID": f"{self.cfg.device_id}-mismatch",
        }
        resp = self.client.request("POST", self.cfg.checkout_start_path, headers=headers, payload={"dry_run": True})
        if resp.status not in self.cfg.reject_statuses:
            raise CheckFailure(f"Mismatch should be rejected, got {resp.status} ({resp.raw[:180]})")
        return f"Session/device mismatch rejected with status {resp.status}."


def _tamper_token(token: str) -> str:
    if len(token) < 8:
        return token + "x"
    i = len(token) // 2
    flipped = "A" if token[i] != "A" else "B"
    return token[:i] + flipped + token[i + 1 :]


def _stable_result_ref(body: Dict[str, Any]) -> Optional[str]:
    for key in ("payment_intent_id", "transaction_id", "order_id", "id"):
        val = body.get(key)
        if isinstance(val, str) and val:
            return f"{key}:{val}"
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run defensive security regression checks for queue and checkout flows.")
    parser.add_argument("--base-url", default=os.getenv("BASE_URL", "http://localhost:8080"))
    parser.add_argument("--access-token", default=os.getenv("ACCESS_TOKEN", ""))
    parser.add_argument("--queue-token", default=os.getenv("QUEUE_TOKEN", ""))
    parser.add_argument("--checkout-grant", default=os.getenv("CHECKOUT_GRANT", ""))
    parser.add_argument("--session-id", default=os.getenv("SESSION_ID", "sess-test"))
    parser.add_argument("--device-id", default=os.getenv("DEVICE_ID", "dev-test"))

    parser.add_argument("--event-id", default=os.getenv("EVENT_ID", "evt-123"))
    parser.add_argument("--order-id", default=os.getenv("ORDER_ID", "ord-123"))
    parser.add_argument("--amount", type=int, default=int(os.getenv("AMOUNT", "100")))
    parser.add_argument("--currency", default=os.getenv("CURRENCY", "USD"))

    parser.add_argument("--queue-header", default=os.getenv("QUEUE_HEADER", "X-Queue-Token"))
    parser.add_argument("--grant-header", default=os.getenv("GRANT_HEADER", "X-Checkout-Grant"))

    parser.add_argument("--checkout-start-path", default=os.getenv("CHECKOUT_START_PATH", "/api/checkout/start"))
    parser.add_argument("--checkout-finalize-path", default=os.getenv("CHECKOUT_FINALIZE_PATH", "/api/checkout/finalize"))
    parser.add_argument("--rate-limit-probe-path", default=os.getenv("RATE_LIMIT_PROBE_PATH", "/api/queue/status"))
    parser.add_argument("--payment-confirm-path", default=os.getenv("PAYMENT_CONFIRM_PATH", "/api/payment/confirm"))

    parser.add_argument("--rate-limit-burst", type=int, default=int(os.getenv("RATE_LIMIT_BURST", "30")))
    parser.add_argument("--rate-limit-interval-ms", type=int, default=int(os.getenv("RATE_LIMIT_INTERVAL_MS", "50")))

    parser.add_argument("--success-statuses", type=int, nargs="+", default=[200, 201, 202])
    parser.add_argument("--reject-statuses", type=int, nargs="+", default=[400, 401, 403, 409, 410, 422, 429])
    return parser


def main() -> int:
    parser = build_parser()
    cfg = parser.parse_args()

    missing = []
    if not cfg.access_token:
        missing.append("ACCESS_TOKEN / --access-token")
    if not cfg.queue_token:
        missing.append("QUEUE_TOKEN / --queue-token")
    if not cfg.checkout_grant:
        missing.append("CHECKOUT_GRANT / --checkout-grant")

    if missing:
        print("Missing required auth values:")
        for item in missing:
            print(f" - {item}")
        return 2

    client = HttpClient(cfg.base_url)
    suite = SecurityRegression(client, cfg)
    return suite.run()


if __name__ == "__main__":
    raise SystemExit(main())
