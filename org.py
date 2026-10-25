import json
import os
import shutil
import subprocess


TARGET_ORG = os.environ.get("SF_TARGET_ORG", "aglab")


# everything goes through the salesforce cli, which uses the login from
# `sf org login web`, so this code never sees a password or token
def sf(*args):
    cmd = [shutil.which("sf") or "sf", *args, "--target-org", TARGET_ORG, "--json"]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f"sf failed: {out.stderr.strip()[:300]}")
    if data.get("status") != 0:
        raise RuntimeError(data.get("message", "sf command failed"))
    return data["result"]


def clean(record):
    out = {}
    for k, v in record.items():
        if k == "attributes":
            continue
        out[k] = clean(v) if isinstance(v, dict) else v
    return out


def query(soql):
    return [clean(r) for r in sf("data", "query", "--query", soql)["records"]]


def values(fields):
    parts = []
    for k, v in fields.items():
        if isinstance(v, bool):
            parts.append(f"{k}={str(v).lower()}")
        else:
            parts.append(f"{k}='{v}'")
    return " ".join(parts)


def create(sobject, fields):
    return sf("data", "create", "record", "--sobject", sobject, "--values", values(fields))["id"]


def update(sobject, record_id, fields):
    sf("data", "update", "record", "--sobject", sobject, "--record-id", record_id, "--values", values(fields))


def delete(sobject, record_id):
    sf("data", "delete", "record", "--sobject", sobject, "--record-id", record_id)
