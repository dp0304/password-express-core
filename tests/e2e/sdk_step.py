# SPDX-License-Identifier: Apache-2.0
"""SDK step of the e2e test: pair a second connection with the Python SDK, check that
another connection's operation id is invisible (A04), then run one approved operation.
Prints markers the driver waits for. argv: broker_url key_path resource_id foreign_op_id"""
import sys

from aipass import Client, pair

broker, key_path, resource_id, foreign_op = sys.argv[1:5]

res = pair("e2e-sdk", key_path=key_path, broker_url=broker, locale="en", wait_timeout=120,
           on_pairing_code=lambda info: print("PAIRING_CODE", info["pairing_code"], flush=True))
assert res.status == "approved", res.status

with Client(broker, key_file=key_path, locale="en") as c:
    try:
        c.get_operation(foreign_op)
        print("FOREIGN VISIBLE", flush=True)
    except Exception as e:  # the SDK raises a typed error carrying the broker code
        code = getattr(e, "code", "")
        print("FOREIGN", code, flush=True)
    op = c.request_operation(resource_id, "postgres.query_view",
                             {"view": "analytics.subscription_daily", "fields": ["day", "subscriptions"], "limit": 5},
                             idempotency_key="sdk-1")
    if op["status"] == "approval_required":
        print("APPROVAL", op["approval_request_id"], flush=True)
        op = c.wait_for_operation(op["operation_id"], timeout=90)
    rows = op.get("result", {}).get("data", {}).get("rows", [])
    assert op["status"] == "succeeded", op
    assert rows and all(set(r) == {"day", "subscriptions"} for r in rows), rows
    print("SDK_OK", len(rows), flush=True)
