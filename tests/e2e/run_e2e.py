#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AI Pass P0 end-to-end acceptance test (design doc §14.1; A01 A02 A04 A05 A07 A09 A11 A13 A18).

Drives the real binaries — `aipass` (trusted devices: "phone" and "laptop"), `aipass-node`
(broker + executor + relay + selfhost sync) and `aipass-mcp` (stdio MCP bridge for the AI) —
plus the Python and TypeScript SDKs against a temporary PostgreSQL cluster with the
lure-store schema. Standard library only.

Usage: tests/e2e/run.sh   (builds the binaries, then runs this file)
Env:   AIPASS_E2E_BIN_DIR (default open-source/target/debug), AIPASS_E2E_PG_PORT (55432),
       AIPASS_E2E_NODE_PORT (57878), AIPASS_E2E_KEEP=1 keeps the work directory,
       AIPASS_E2E_SKIP_SDK=1 skips the Python and TypeScript SDK steps.
"""

import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("AIPASS_E2E_BIN_DIR", os.path.join(ROOT, "target", "debug"))
PG_PORT = int(os.environ.get("AIPASS_E2E_PG_PORT", "55432"))
NODE_PORT = int(os.environ.get("AIPASS_E2E_NODE_PORT", "57878"))
NODE_URL = f"http://127.0.0.1:{NODE_PORT}"
VIEW = "analytics.subscription_daily"

PROCS = []
RESULTS = []
TRANSCRIPTS = []  # every byte an AI-facing tool produced


def log(msg):
    print(f"[e2e] {msg}", flush=True)


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    log(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        raise SystemExit(f"assertion failed: {name}: {detail}")


def which(tool):
    p = shutil.which(tool)
    if p:
        return p
    for prefix in ("/opt/homebrew/opt/postgresql@17/bin", "/opt/homebrew/bin", "/usr/local/opt/postgresql@17/bin", "/usr/lib/postgresql/17/bin"):
        c = os.path.join(prefix, tool)
        if os.path.exists(c):
            return c
    raise SystemExit(f"{tool} not found (install PostgreSQL 17)")


def run(args, env=None, input_text=None, check_rc=True, timeout=120):
    r = subprocess.run(args, env=env, input=input_text, capture_output=True, text=True, timeout=timeout)
    if check_rc and r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(args)}\nstdout:{r.stdout}\nstderr:{r.stderr}")
    return r


class Work:
    def __init__(self):
        base = os.environ.get("AIPASS_E2E_WORK")
        self.dir = tempfile.mkdtemp(prefix="aipass-e2e-", dir=base)
        self.pgdata = os.path.join(self.dir, "pg")
        self.pgsock = tempfile.mkdtemp(prefix="aipg-", dir="/tmp")  # socket paths are limited to ~103 bytes
        self.cli_home = os.path.join(self.dir, "phone")
        self.agent_home = os.path.join(self.dir, "agent")
        self.node_dir = os.path.join(self.dir, "node")
        self.laptop_home = os.path.join(self.dir, "laptop")  # second trusted device (A11)
        os.makedirs(os.path.join(self.agent_home, ".aipass"))
        self.db_password = "e2e-" + secrets.token_urlsafe(24)
        self.passphrase = "phone-" + secrets.token_urlsafe(12)

    def path(self, *p):
        return os.path.join(self.dir, *p)


# ---------------------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------------------

PG_ENV = dict(os.environ, LC_ALL="C", LANG="C")  # macOS: postmaster refuses an unset locale


def start_postgres(w):
    log(f"starting temporary PostgreSQL on 127.0.0.1:{PG_PORT}")
    pwfile = w.path("pg-super.pw")
    with open(pwfile, "w") as f:
        f.write(secrets.token_urlsafe(16))
    run([which("initdb"), "-D", w.pgdata, "-U", "postgres", "--auth-local=trust", "--auth-host=scram-sha-256", f"--pwfile={pwfile}", "-E", "UTF8", "--locale=C"], env=PG_ENV)
    run([which("pg_ctl"), "-D", w.pgdata, "-l", w.path("pg.log"), "-w", "-t", "30", "start",
         "-o", f"-p {PG_PORT} -k {w.pgsock} -c listen_addresses=127.0.0.1"], env=PG_ENV)
    psql = [which("psql"), "-h", w.pgsock, "-p", str(PG_PORT), "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"]
    run(psql + ["-d", "postgres", "-c", "CREATE DATABASE lure"])
    run(psql + ["-d", "lure", "-f", os.path.join(ROOT, "deploy", "examples", "lure-store", "schema.sql")])
    # password set out-of-band through stdin (never on a command line)
    run(psql + ["-d", "lure"], input_text=f"ALTER ROLE lure_readonly PASSWORD '{w.db_password}';\n")


def stop_postgres(w):
    if os.path.exists(os.path.join(w.pgdata, "postmaster.pid")):
        subprocess.run([which("pg_ctl"), "-D", w.pgdata, "-m", "fast", "-w", "stop"], capture_output=True, env=PG_ENV)


# ---------------------------------------------------------------------------------------
# helpers for the binaries
# ---------------------------------------------------------------------------------------

def cli_env(w, home=None):
    e = dict(os.environ)
    # the harness has no terminal: approval-class commands need the documented opt-in
    # (AIPASS_UNATTENDED_APPROVALS=1, design §9.3 compatible mode — tests only)
    e.update({"AIPASS_HOME": home or w.cli_home, "AIPASS_PASSPHRASE": w.passphrase, "AIPASS_LANG": "en", "AIPASS_LOG": "warn",
              "AIPASS_UNATTENDED_APPROVALS": "1"})
    e.pop("AIPASS_BROKER_URL", None)
    return e


def agent_env(w):
    e = dict(os.environ)
    e.update({"HOME": w.agent_home, "AIPASS_HOME": os.path.join(w.agent_home, ".aipass"), "AIPASS_LANG": "en", "AIPASS_LOG": "warn"})
    for k in ("AIPASS_PASSPHRASE", "AIPASS_BROKER_URL", "E2E_DB_PASSWORD", "AIPASS_UNATTENDED_APPROVALS"):
        e.pop(k, None)
    return e


def aipass(w, *args, input_text=None, check_rc=True, extra_env=None, home=None):
    env = cli_env(w, home)
    if extra_env:
        env.update(extra_env)
    return run([os.path.join(BIN, "aipass"), *args], env=env, input_text=input_text, check_rc=check_rc)


def spawn(args, env, stdout_path, stdin=None):
    out = open(stdout_path, "w")
    p = subprocess.Popen(args, env=env, stdout=out, stderr=subprocess.STDOUT, stdin=stdin, text=True)
    PROCS.append(p)
    return p


def wait_for_file_match(path, pattern, timeout=60, proc=None):
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < deadline:
        try:
            with open(path) as f:
                m = rx.search(f.read())
                if m:
                    return m
        except FileNotFoundError:
            pass
        if proc is not None and proc.poll() is not None:
            with open(path) as f:
                raise SystemExit(f"process exited early ({proc.returncode}):\n{f.read()}")
        time.sleep(0.2)
    with open(path) as f:
        raise SystemExit(f"timeout waiting for /{pattern}/ in {path}:\n{f.read()}")


def http_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


class McpStdio:
    """Minimal MCP client over the bridge's stdio (JSON-RPC, one message per line)."""

    def __init__(self, w, connection_id):
        args = [os.path.join(BIN, "aipass-mcp"), "stdio", "--broker", NODE_URL, "--connection", connection_id]
        self.p = subprocess.Popen(args, env=agent_env(w), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        PROCS.append(self.p)
        self.next_id = 1
        self.stderr = []
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        for line in self.p.stderr:
            self.stderr.append(line)
            TRANSCRIPTS.append(line)

    def send(self, obj):
        line = json.dumps(obj)
        TRANSCRIPTS.append(line)
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def request(self, method, params=None):
        rid = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise SystemExit("MCP bridge closed stdout; stderr:\n" + "".join(self.stderr))
            TRANSCRIPTS.append(line)
            msg = json.loads(line)
            if msg.get("id") == rid:
                return msg

    def call(self, tool, args):
        r = self.request("tools/call", {"name": tool, "arguments": args})
        if "error" in r:
            raise SystemExit(f"JSON-RPC error from {tool}: {r['error']}")
        res = r["result"]
        if res.get("structuredContent") is not None:
            return res.get("isError", False), res["structuredContent"]
        text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        try:  # error results: the JSON envelope first, then a bilingual hint
            return res.get("isError", False), json.JSONDecoder().raw_decode(text.lstrip())[0]
        except ValueError:
            return res.get("isError", False), {"text": text}

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


def error_code(payload):
    if isinstance(payload, dict):
        if "error" in payload and isinstance(payload["error"], dict):
            return payload["error"].get("code")
    return None


# ---------------------------------------------------------------------------------------
# the scenario
# ---------------------------------------------------------------------------------------

def start_node(w):
    os.makedirs(w.node_dir)
    with open(w.path("node.toml"), "w") as f:
        f.write(
            f'[node]\nname = "e2e-node"\ndata_dir = "{w.node_dir}"\nlisten = "127.0.0.1:{NODE_PORT}"\n\n'
            '[executor]\nprotection_level = "compatible"\n\n[log]\nformat = "json"\nfilter = "info"\n'
        )
    node_env = dict(os.environ)
    for k in ("AIPASS_PASSPHRASE", "E2E_DB_PASSWORD"):
        node_env.pop(k, None)
    node_env["AIPASS_LOG"] = "info"
    log("starting aipass-node")
    node = spawn([os.path.join(BIN, "aipass-node"), "-c", w.path("node.toml"), "run"], node_env, w.path("node.log"))
    deadline = time.time() + 30
    while True:
        try:
            h = http_json(NODE_URL + "/v1/health")
            break
        except Exception:
            if node.poll() is not None or time.time() > deadline:
                raise SystemExit("node did not start:\n" + open(w.path("node.log")).read())
            time.sleep(0.3)
    check("node health", h.get("status") == "ok", json.dumps(h))
    check("node reports compatible protection honestly", h.get("protection_level") == "compatible", json.dumps(h))
    return node_env


def read_until(proc, pattern, lines, timeout=60):
    """Read `proc`'s stdout line by line until `pattern` matches (returns the match)."""
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line)
        m = rx.search(line)
        if m:
            return m
    raise SystemExit(f"no /{pattern}/ from process:\n{''.join(lines)}")


def second_device(w):
    """A second CLI device joins the vault through the node (relay pairing, selfhost sync),
    then a concurrent edit on both devices produces a conflict that pauses automatic use and
    is resolved on a trusted device (A11)."""
    log("second trusted device: aipass device join ↔ aipass device pair")
    join = subprocess.Popen([os.path.join(BIN, "aipass"), "device", "join", "--device-name", "e2e-laptop", "--relay", NODE_URL, "--timeout-secs", "120"],
                            env=cli_env(w, w.laptop_home), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    PROCS.append(join)
    jl = []
    uri = read_until(join, r"(aipass://pair\?\S+)", jl, 30).group(1)
    dev = subprocess.Popen([os.path.join(BIN, "aipass"), "device", "pair", "--uri", uri, "--timeout-secs", "120"], env=cli_env(w),
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    PROCS.append(dev)
    dl = []
    phone_code = read_until(dev, r"Pairing code: (\d{6})", dl, 60).group(1)
    laptop_code = read_until(join, r"Pairing code: (\d{6})", jl, 60).group(1)
    check("second device: both sides show the same pairing code (SAS)", phone_code == laptop_code, f"phone={phone_code} laptop={laptop_code}")
    dev.stdin.write(laptop_code + "\n")
    dev.stdin.flush()
    rest, _ = dev.communicate(timeout=60)
    check("phone confirmed the new trusted device", dev.returncode == 0 and "joined:" in rest, "".join(dl) + rest)
    jrest, _ = join.communicate(timeout=60)
    check("second device joined the vault (member chain + checkpoint verified from the node)", join.returncode == 0 and "joined the vault" in jrest, "".join(jl) + jrest)

    def laptop(*a, **k):
        return aipass(w, *a, home=w.laptop_home, **k)

    st = json.loads(laptop("--json", "vault", "status").stdout)
    check("second device uses the node's selfhost storage", st.get("storage_kind") == "selfhost", json.dumps(st))
    laptop("sync")
    items = json.loads(laptop("--json", "item", "list").stdout)
    check("second device synced the DB credential entry through the node", any(i["title"] == "Lure store DB" for i in items), json.dumps(items))
    devs = json.loads(aipass(w, "--json", "device", "list").stdout)
    check("phone lists the second device as active", any(d["name"] == "e2e-laptop" and d["status"] == "active" for d in devs), json.dumps(devs))

    # A11: concurrent edits of the same secret on two devices
    log("A11: concurrent edits on two devices")
    out = aipass(w, "item", "add", "--kind", "login", "--title", "Shop admin", "--username", "admin", "--url", "https://shop.example.com",
                 "--secret-env", "E2E_ITEM_SECRET", extra_env={"E2E_ITEM_SECRET": "base-" + secrets.token_urlsafe(8)}).stdout.strip()
    shop = out.splitlines()[-1]
    laptop("sync")
    check("second device sees the new item", any(i["entry_id"] == shop for i in json.loads(laptop("--json", "item", "list").stdout)), "")
    aipass(w, "item", "edit", shop, "--secret-env", "E2E_ITEM_SECRET", extra_env={"E2E_ITEM_SECRET": "phone-" + secrets.token_urlsafe(8)})
    # the laptop has not pulled the phone's edit: its save rebases onto it and must conflict
    laptop("item", "edit", shop, "--secret-env", "E2E_ITEM_SECRET", extra_env={"E2E_ITEM_SECRET": "laptop-" + secrets.token_urlsafe(8)})
    aipass(w, "sync")
    laptop("sync")
    for name, home in (("phone", None), ("laptop", w.laptop_home)):
        conf = json.loads(aipass(w, "conflicts", "list", home=home).stdout)
        mine = [c for c in conf if c["entry_id"] == shop]
        check(f"A11: {name} shows the conflict (both versions kept)", len(mine) == 1 and len(mine[0]["conflict_versions"]) >= 1, json.dumps(conf))
    listed = [i for i in json.loads(aipass(w, "--json", "item", "list").stdout) if i["entry_id"] == shop]
    check("A11: the conflicted entry is flagged (automatic use paused)", listed and listed[0].get("has_conflict") is True, json.dumps(listed))
    c0 = [c for c in json.loads(aipass(w, "conflicts", "list").stdout) if c["entry_id"] == shop][0]
    keep = max(c0["conflict_versions"] + [c0["current_version"]])
    aipass(w, "conflicts", "resolve", shop, "--keep", str(keep))
    laptop("sync")
    left = [c for c in json.loads(laptop("conflicts", "list").stdout) if c["entry_id"] == shop]
    check("A11: conflict resolved on a trusted device and the resolution synced", not left, json.dumps(left))


def scenario(w):
    # 1. node first: it is also the self-hosted ciphertext sync service (enroll token)
    node_env = start_node(w)
    token = run([os.path.join(BIN, "aipass-node"), "-c", w.path("node.toml"), "enroll-token", "create", "--uses", "1", "--ttl-hours", "1"], env=node_env).stdout.strip()
    check("enroll token issued", token.startswith("aipe_"), "")

    # vault on the "phone" (trusted device = the CLI), stored on the node's sync API
    log("creating the vault on the trusted device (CLI) with selfhost storage on the node")
    out = aipass(w, "vault", "init", "--device-name", "e2e-phone", "--storage", "selfhost", "--base-url", NODE_URL,
                 "--secret-env", "E2E_ENROLL_TOKEN", "--kit-out", w.path("recovery-kit.txt"), extra_env={"E2E_ENROLL_TOKEN": token}).stdout
    check("vault created on the node's sync API (POST /v1/vaults + idempotent genesis)", "vault_id: vlt_" in out, out)
    vault_id = re.search(r"vault_id: (vlt_\S+)", out).group(1)
    w.vault_id = vault_id
    st = json.loads(aipass(w, "--json", "vault", "status").stdout)
    check("vault storage is selfhost", st.get("storage_kind") == "selfhost", json.dumps(st))
    check("ciphertext objects stored by the node", any(vault_id in d for d, _, _ in os.walk(w.node_dir)), "vault namespace missing under the node data dir")
    r = aipass(w, "vault", "init", "--device-name", "intruder", "--storage", "selfhost", "--base-url", NODE_URL, "--secret-env", "E2E_ENROLL_TOKEN",
               "--kit-out", w.path("kit2.txt"), extra_env={"E2E_ENROLL_TOKEN": token}, home=w.path("intruder"), check_rc=False)
    check("a used (single-use) enroll token cannot create another vault", r.returncode != 0, r.stdout + r.stderr)

    # 2. store the DB credential (A01: the secret only enters the trusted client)
    out = aipass(
        w, "item", "add", "--kind", "database", "--title", "Lure store DB", "--username", "lure_readonly",
        "--secret-env", "E2E_DB_PASSWORD", "--db-host", "127.0.0.1", "--db-port", str(PG_PORT), "--db-name", "lure", "--db-sslmode", "disable",
        extra_env={"E2E_DB_PASSWORD": w.db_password},
    ).stdout.strip()
    entry_id = out.splitlines()[-1]
    check("credential stored in the vault", entry_id.startswith("ent_"), out)
    shown = aipass(w, "item", "show", entry_id).stdout
    check("item show masks the secret", w.db_password not in shown, "secret visible in item show")

    # 3. pair the node as executor (§5): node shows the link, CLI scans, both show the SAS
    log("pairing the node as executor")
    pair_p = spawn([os.path.join(BIN, "aipass-node"), "-c", w.path("node.toml"), "pair", "--no-qr", "--timeout-secs", "120"], node_env, w.path("node-pair.log"))
    uri = wait_for_file_match(w.path("node-pair.log"), r"(aipass://pair\?\S+)", 30, pair_p).group(1)
    dev = subprocess.Popen([os.path.join(BIN, "aipass"), "device", "pair", "--uri", uri, "--timeout-secs", "120"], env=cli_env(w),
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    PROCS.append(dev)
    dev_lines = []
    cli_code = None
    deadline = time.time() + 60
    while cli_code is None and time.time() < deadline:
        line = dev.stdout.readline()
        if not line:
            break
        dev_lines.append(line)
        m = re.search(r"Pairing code: (\d{6})", line)
        if m:
            cli_code = m.group(1)
    node_code = wait_for_file_match(w.path("node-pair.log"), r"Pairing code: (\d{6})", 30, pair_p).group(1)
    check("both sides show the same pairing code (SAS)", cli_code == node_code, f"cli={cli_code} node={node_code} {''.join(dev_lines)}")
    dev.stdin.write(node_code + "\n")
    dev.stdin.flush()
    rest, _ = dev.communicate(timeout=60)
    check("trusted device confirmed the executor", dev.returncode == 0 and "executor_id: exe_" in rest, "".join(dev_lines) + rest)
    pair_p.wait(timeout=60)
    check("node received pairing.welcome", pair_p.returncode == 0, open(w.path("node-pair.log")).read())

    # 4. a second trusted device joins through the node (relay pairing + selfhost sync), A11
    second_device(w)

    # 5. resource: only a reference to the vault entry is sent to the broker
    cfg = {"host": "127.0.0.1", "port": PG_PORT, "dbname": "lure", "sslmode": "disable",
           "allowed_views": {VIEW: {"fields": ["day", "plan", "subscriptions", "mrr_cents"]}}}
    with open(w.path("lure-db.json"), "w") as f:
        json.dump(cfg, f)
    out = aipass(w, "resource", "add", "--alias", "lure-db", "--service", "PostgreSQL", "--connector", "postgres", "--project", "lure-store",
                 "--environment", "test", "--entry", entry_id, "--config", w.path("lure-db.json")).stdout.strip()
    resource_id = out.splitlines()[-1]
    check("resource registered", resource_id.startswith("res_"), out)
    bad = dict(cfg, password="x")
    with open(w.path("bad.json"), "w") as f:
        json.dump(bad, f)
    r = aipass(w, "resource", "add", "--alias", "bad", "--connector", "postgres", "--project", "lure-store", "--entry", entry_id,
               "--config", w.path("bad.json"), check_rc=False)
    check("resource config with a secret / unknown key is rejected", r.returncode != 0 and "INVALID_REQUEST" in (r.stdout + r.stderr), r.stdout + r.stderr)

    # 6. pair the AI connection (aipass-mcp pair) and approve it on the trusted device
    log("pairing the MCP connection")
    mcp_pair = spawn([os.path.join(BIN, "aipass-mcp"), "pair", "--host", "codex", "--name", "e2e-agent", "--broker", NODE_URL], agent_env(w), w.path("mcp-pair.log"))
    mcp_code = wait_for_file_match(w.path("mcp-pair.log"), r"Pairing code:\s+(\d{6})\b", 30, mcp_pair).group(1)
    conns = json.loads(aipass(w, "--json", "connections", "list").stdout)["connections"]
    pending = [c for c in conns if c["status"] == "pending" and c["display_name"] == "e2e-agent"]
    check("pending connection visible to the trusted device", len(pending) == 1, json.dumps(conns))
    # the CLI never lists the code (the user must read it off the AI host, not copy it)
    check("A05: the pairing code is not echoed by the trusted device's listing", mcp_code not in json.dumps(pending), json.dumps(pending))
    conn_id = pending[0]["connection_id"]
    # A05: approving needs the code shown on the AI host; a wrong code is refused
    wrong = "%06d" % ((int(mcp_code) + 1) % 1000000)
    r = aipass(w, "connections", "approve", conn_id, "--projects", "*", "--code", wrong, check_rc=False)
    check("A05: a wrong pairing code is refused", r.returncode != 0 and "mismatch" in (r.stdout + r.stderr), r.stdout + r.stderr)
    r = aipass(w, "connections", "approve", conn_id, "--projects", "*", "--code", mcp_code, check_rc=False,
               extra_env={"AIPASS_UNATTENDED_APPROVALS": "0"})
    check("human-presence guard: approving without a terminal (no opt-in) is refused", r.returncode != 0 and "interactive terminal" in r.stderr, r.stderr)
    aipass(w, "connections", "approve", conn_id, "--projects", "*", "--code", mcp_code)
    mcp_pair.wait(timeout=60)
    pair_out = open(w.path("mcp-pair.log")).read()
    TRANSCRIPTS.append(pair_out)
    check("connection key stored after approval", mcp_pair.returncode == 0 and conn_id in pair_out, pair_out)

    # 7. the AI side
    mcp = McpStdio(w, conn_id)
    init = mcp.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}})
    check("MCP initialize", "result" in init, json.dumps(init))
    mcp.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools = [t["name"] for t in mcp.request("tools/list")["result"]["tools"]]
    forbidden = [t for t in tools if re.search(r"password|secret|export|cookie|token|reveal|exec", t)]
    check("A02: no tool can return a raw credential", not forbidden and "operations_request" in tools, json.dumps(tools))

    _, res = mcp.call("resources_list", {})
    rv = [x for x in res["resources"] if x["resource_id"] == resource_id]
    check("resources_list shows the resource without config", len(rv) == 1 and "config" not in rv[0] and "127.0.0.1" not in json.dumps(rv[0]), json.dumps(res))

    params = {"view": VIEW, "fields": ["day", "plan", "subscriptions"], "order_by": [{"field": "day"}], "limit": 50}
    _, op = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": params, "idempotency_key": "e2e-1"})
    check("operations_request → approval_required", op.get("status") == "approval_required" and op.get("approval_request_id", "").startswith("apr_"), json.dumps(op))
    check("approval message matches §12.2", op.get("message") == "请在已配对的手机或可信客户端批准本次访问。" or "approve" in (op.get("message") or "").lower(), json.dumps(op))
    first_apr = op["approval_request_id"]
    first_op = op["operation_id"]

    # 8. approve on the trusted device: digest-bound signature + credential sealed to the executor
    card = aipass(w, "approvals", "show", first_apr).stdout
    check("approval card shows connection, resource, executor and recipients",
          "e2e-agent" in card and "lure-db" in card and "e2e-node" in card and "compatible" in card, card)
    out = aipass(w, "approvals", "approve", first_apr, "--yes").stdout
    check("trusted device approved", "approved" in out, out)

    st = None
    for _ in range(60):
        _, st = mcp.call("operations_status", {"operation_id": first_op})
        if st.get("status") in ("succeeded", "failed", "unknown", "denied", "expired", "cancelled"):
            break
        time.sleep(0.5)
    check("operation succeeded after approval", st.get("status") == "succeeded", json.dumps(st))
    rows = st["result"]["data"]["rows"]
    keys = set()
    for row in rows:
        keys |= set(row.keys())
    check("result has only day/plan/subscriptions", len(rows) > 0 and keys == {"day", "plan", "subscriptions"}, json.dumps(rows[:3]))
    check("no customer e-mail in the result", "@example.com" not in json.dumps(st), "")

    # 9. A07: forbidden view / field
    for label, p in (
        ("forbidden view", {"view": "shop.customers", "fields": ["email"]}),
        ("forbidden field", {"view": VIEW, "fields": ["day", "email"]}),
        ("function in field name", {"view": VIEW, "fields": ["pg_read_file('/etc/passwd')"]}),
    ):
        is_err, r = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": p, "idempotency_key": "e2e-" + secrets.token_hex(4)})
        check(f"A07: {label} → SCOPE_DENIED / INVALID_REQUEST", is_err and error_code(r) in ("SCOPE_DENIED", "INVALID_REQUEST"), json.dumps(r))

    # 10. task grant reuse, then A05 widening needs a new approval
    _, again = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": dict(params, limit=5), "idempotency_key": "e2e-2"})
    if again.get("status") not in ("succeeded",):
        for _ in range(40):
            _, again = mcp.call("operations_status", {"operation_id": again["operation_id"]})
            if again.get("status") not in ("authorized", "running", "policy_checked", "received"):
                break
            time.sleep(0.25)
    check("same scope within the task grant runs without a new approval", again.get("status") == "succeeded", json.dumps(again))
    wide = dict(params, fields=["day", "plan", "subscriptions", "mrr_cents"])
    _, w_op = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": wide, "idempotency_key": "e2e-3"})
    check("A05: widening after approval → new approval required", w_op.get("status") == "approval_required" and w_op.get("approval_request_id") != first_apr, json.dumps(w_op))
    _, idem = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": wide, "idempotency_key": "e2e-1"})
    check("idempotency key reused with other parameters → IDEMPOTENCY_CONFLICT", error_code(idem) == "IDEMPOTENCY_CONFLICT", json.dumps(idem))

    # 11. A04: ids are not capabilities — an operation id of another connection is invisible,
    # and a forged connection id without its key cannot authenticate
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "operations_status", "arguments": {"operation_id": first_op}}},
    ]
    forged = subprocess.run([os.path.join(BIN, "aipass-mcp"), "stdio", "--broker", NODE_URL, "--connection", "conn_01jzzzzzzzzzzzzzzzzzzzzzzz"],
                            env=agent_env(w), input="".join(json.dumps(m) + "\n" for m in msgs), capture_output=True, text=True, timeout=30)
    TRANSCRIPTS.append(forged.stdout + forged.stderr)
    reply = [json.loads(l) for l in forged.stdout.splitlines() if l.strip().startswith("{")]
    r2 = [m for m in reply if m.get("id") == 2]
    denied = bool(r2) and (r2[0].get("result", {}).get("isError") is True or "error" in r2[0]) and "succeeded" not in json.dumps(r2[0])
    check("A04: a forged connection id (no key) cannot read another connection's operation", denied, forged.stdout[-600:] + forged.stderr[-300:])

    # 12. the phone path: approval.request reached the device mailbox through the E2E relay,
    # and a decision sent back through the relay is applied by the node's mailbox consumer
    wide_apr = w_op["approval_request_id"]
    inbox = json.loads(aipass(w, "--json", "inbox").stdout)["messages"]
    check("relay: approval.request delivered (sealed) to the trusted device's mailbox",
          any(m["type"] == "approval.request" and m["subject"] == wide_apr for m in inbox), json.dumps(inbox))
    out = aipass(w, "approvals", "approve", wide_apr, "--via-relay", "--yes").stdout
    check("relay: signed decision sent through the relay", "relay" in out, out)
    for _ in range(60):
        _, wst = mcp.call("operations_status", {"operation_id": w_op["operation_id"]})
        if wst.get("status") in ("succeeded", "failed", "unknown", "denied", "expired", "cancelled"):
            break
        time.sleep(0.5)
    wkeys = set().union(*[set(r) for r in wst.get("result", {}).get("data", {}).get("rows", [{}])])
    check("relay-approved widened operation succeeded with mrr_cents", wst.get("status") == "succeeded" and "mrr_cents" in wkeys, json.dumps(wst)[:400])

    # 12b. connection control through the relay (§4): signed connection.control pause/resume,
    # confirmed by a sealed state.snapshot from the broker
    out = json.loads(aipass(w, "--json", "connections", "pause", conn_id, "--via-relay").stdout)
    check("relay: connection.control pause confirmed by the broker's state snapshot", out.get("confirmed") is True and out.get("status") == "paused", json.dumps(out))
    is_err, paused = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": dict(params, limit=2), "idempotency_key": "e2e-paused"})
    check("paused connection → CONNECTION_PAUSED", is_err and error_code(paused) == "CONNECTION_PAUSED", json.dumps(paused))
    out = json.loads(aipass(w, "--json", "connections", "resume", conn_id, "--via-relay").stdout)
    check("relay: connection.control resume confirmed", out.get("confirmed") is True and out.get("status") == "active", json.dumps(out))

    # 13. A09: revoke → the grants stop serving within 5 s (the first one as a device-signed
    # grant.revoke through the relay, answered by a sealed revoke.report)
    grants = json.loads(aipass(w, "--json", "grants", "list", "--status", "active").stdout)["grants"]
    check("active grants present", len(grants) >= 1, json.dumps(grants))
    t0 = time.time()
    for i, g in enumerate(grants):
        via = ["--via-relay"] if i == 0 else []
        rep = json.loads(aipass(w, "--json", "grants", "revoke", g["grant_id"], "--level", "end_sessions", *via).stdout)
        check("revocation report: stop_access + end_sessions done" + (" (via relay)" if via else ""),
              rep.get("grant_id") == g["grant_id"] and rep["stop_access"]["status"] == "done" and rep["end_sessions"]["status"] in ("done", "not_applicable"), json.dumps(rep))
    gid = grants[0]["grant_id"]
    _, after = mcp.call("operations_request", {"resource_id": resource_id, "operation": "postgres.query_view", "parameters": dict(params, limit=3), "idempotency_key": "e2e-4"})
    elapsed = time.time() - t0
    blocked = after.get("status") == "approval_required" or error_code(after) == "GRANT_REVOKED" or (after.get("error") or {}).get("code") == "GRANT_REVOKED"
    check("A09: after revoke the next request is not served by the old grants (≤ 5 s)", blocked and elapsed <= 5.0, f"{elapsed:.2f}s {json.dumps(after)}")
    g2 = json.loads(aipass(w, "--json", "grants", "list").stdout)["grants"]
    check("grant shows revoked", any(g["grant_id"] == gid and g["status"] == "revoked" for g in g2), json.dumps(g2))

    audit = json.loads(aipass(w, "--json", "audit", "verify").stdout)
    check("audit chain verifies", audit.get("valid") is True, json.dumps(audit))
    mcp.close()
    return resource_id, first_op


def sdk_step(w, resource_id, foreign_op):
    if os.environ.get("AIPASS_E2E_SKIP_SDK") == "1":
        log("SDK step skipped (AIPASS_E2E_SKIP_SDK=1)")
        return
    sdk = os.path.join(ROOT, "sdk", "python")
    uv = shutil.which("uv")
    if not uv or not os.path.isdir(sdk):
        log("SDK step skipped (uv or sdk/python missing)")
        return
    log("Python SDK: pairing a second connection")
    out_path = w.path("sdk.log")
    env = agent_env(w)
    env["UV_PROJECT_ENVIRONMENT"] = w.path("sdk-venv")
    p = spawn([uv, "run", "--quiet", "--project", sdk, "python", os.path.join(ROOT, "tests", "e2e", "sdk_step.py"), NODE_URL, w.path("sdk.key"), resource_id, foreign_op],
              env, out_path)
    code = wait_for_file_match(out_path, r"PAIRING_CODE (\d{6})", 180, p).group(1)
    conns = json.loads(aipass(w, "--json", "connections", "list").stdout)["connections"]
    pend = [c for c in conns if c["status"] == "pending" and c["display_name"] == "e2e-sdk"]
    check("SDK connection pending", len(pend) == 1, json.dumps(conns))
    aipass(w, "connections", "approve", pend[0]["connection_id"], "--projects", "*", "--code", code)
    apr = wait_for_file_match(out_path, r"APPROVAL (apr_\S+)", 60, p).group(1)
    aipass(w, "approvals", "approve", apr, "--yes")
    p.wait(timeout=120)
    text = open(out_path).read()
    TRANSCRIPTS.append(text)
    check("A04 (SDK): another connection's operation id → NOT_FOUND", "FOREIGN NOT_FOUND" in text, text)
    check("SDK operation succeeded", p.returncode == 0 and "SDK_OK" in text, text)


def ts_sdk_step(w, resource_id, foreign_op):
    if os.environ.get("AIPASS_E2E_SKIP_SDK") == "1":
        log("TS SDK step skipped (AIPASS_E2E_SKIP_SDK=1)")
        return
    dist = os.path.join(ROOT, "sdk", "typescript", "dist")
    node = shutil.which("node")
    if not node or not os.path.exists(os.path.join(dist, "index.js")):
        raise SystemExit("TS SDK step needs node and a built sdk/typescript/dist (run.sh builds it)")
    log("TypeScript SDK: pairing a third connection against the real node")
    out_path = w.path("ts-sdk.log")
    p = spawn([node, os.path.join(ROOT, "tests", "e2e", "sdk_ts_step.mjs"), NODE_URL, w.path("ts-sdk.key"), resource_id, foreign_op, dist],
              agent_env(w), out_path)
    code = wait_for_file_match(out_path, r"PAIRING_CODE (\d{6})", 60, p).group(1)
    conns = json.loads(aipass(w, "--json", "connections", "list").stdout)["connections"]
    pend = [c for c in conns if c["status"] == "pending" and c["display_name"] == "e2e-ts-sdk"]
    check("TS SDK connection pending", len(pend) == 1, json.dumps(conns))
    # approved with a device-signed connection.decision through the relay (§4); the code is
    # checked against the sealed connection.pair_request in this device's relay mailbox
    wrong = "%06d" % ((int(code) + 1) % 1000000)
    r = aipass(w, "connections", "approve", pend[0]["connection_id"], "--projects", "*", "--via-relay", "--code", wrong, check_rc=False)
    check("A05 (relay): a wrong pairing code is refused", r.returncode != 0 and "mismatch" in (r.stdout + r.stderr), r.stdout + r.stderr)
    out = json.loads(aipass(w, "--json", "connections", "approve", pend[0]["connection_id"], "--projects", "*", "--via-relay", "--code", code).stdout)
    check("relay: connection.decision approve confirmed by the broker", out.get("confirmed") is True and out.get("status") == "active", json.dumps(out))
    apr = wait_for_file_match(out_path, r"APPROVAL (apr_\S+)", 60, p).group(1)
    aipass(w, "approvals", "approve", apr, "--yes")
    p.wait(timeout=120)
    text = open(out_path).read()
    TRANSCRIPTS.append(text)
    check("A04 (TS SDK): another connection's operation id → NOT_FOUND", "FOREIGN NOT_FOUND" in text, text)
    check("TS SDK operation succeeded with only the approved fields", p.returncode == 0 and "TS_SDK_OK" in text, text)


def recovery_drill(w, vault_id):
    """A13 on the CLI without a phone: a fresh device recovers the vault from the node's
    selfhost storage with the recovery key from the kit, joins as a new owner (nothing is
    revoked automatically), then revokes the "lost" laptop and lists the rotation tasks."""
    log("A13: recovering the vault on a fresh CLI device with the recovery key")
    home = w.path("recovered")
    out = aipass(w, "vault", "recover", "--vault-id", vault_id, "--device-name", "e2e-recovered", "--storage", "selfhost", "--base-url", NODE_URL,
                 "--recovery-key-file", w.path("recovery-kit.txt"), home=home).stdout
    check("A13: fresh device recovered the vault from storage with the recovery key", vault_id in out and "No device was revoked" in out, out)
    items = json.loads(aipass(w, "--json", "item", "list", home=home).stdout)
    check("A13: recovered device reads the vault items", any(i["title"] == "Lure store DB" for i in items), json.dumps(items))
    devs = json.loads(aipass(w, "--json", "device", "list", home=home).stdout)
    laptop = [d for d in devs if d["name"] == "e2e-laptop"]
    check("A13: nothing revoked automatically (old devices still active)",
          laptop and all(d["status"] == "active" for d in devs if not d.get("is_recovery_key")), json.dumps(devs))
    out = aipass(w, "rotation", "list", home=home).stdout
    check("A13: no rotation tasks before a revocation", "no credentials to rotate" in out, out)
    aipass(w, "device", "revoke", laptop[0]["device_id"], home=home)
    tasks = json.loads(aipass(w, "--json", "rotation", "list", home=home).stdout)
    check("A13: revoking the lost device lists its long-term credentials for rotation", any(t["title"] == "Lure store DB" for t in tasks), json.dumps(tasks))
    r = aipass(w, "sync", home=w.laptop_home, check_rc=False)
    text = (r.stdout + r.stderr).lower()
    check("A13: the revoked device can no longer sync the vault", r.returncode != 0 or "revoked" in text or "error" in text, r.stdout + r.stderr)


def node_log_checks(w):
    text = open(w.path("node.log"), errors="replace").read()
    check("node: relay control channel stayed up (mailbox consumer healthy)", "control channel lost" not in text, "")
    check("node: relay deliveries to trusted devices succeeded", "could not post relay reply" not in text and "relay message rejected" not in text, "")


def leak_scan(w):
    log("scanning every AI-facing output, log and database for the test credential")
    needles = [w.db_password, f"lure_readonly:{w.db_password}", f"postgres://lure_readonly:{w.db_password}@", "password=" + w.db_password]
    blob = "\n".join(TRANSCRIPTS)
    for n in needles:
        check("A01/A18: credential absent from MCP/SDK transcripts", n not in blob, "found in transcript")
    scanned = 0
    hits = []
    for root in (w.node_dir, w.agent_home):
        for dirpath, _, files in os.walk(root):
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    data = open(path, "rb").read()
                except OSError:
                    continue
                scanned += 1
                if w.db_password.encode() in data:
                    hits.append(path)
    for name in ("node.log", "node-pair.log", "mcp-pair.log", "sdk.log", "ts-sdk.log"):
        path = w.path(name)
        if os.path.exists(path):
            scanned += 1
            if w.db_password in open(path, errors="replace").read():
                hits.append(path)
    check(f"A01/A18: credential absent from node logs, broker.db, relay.db, sync blobs ({scanned} files)", not hits, ", ".join(hits))


def main():
    w = Work()
    log(f"work directory {w.dir}")
    ok = False
    try:
        start_postgres(w)
        resource_id, op = scenario(w)
        sdk_step(w, resource_id, op)
        ts_sdk_step(w, resource_id, op)
        recovery_drill(w, w.vault_id)
        node_log_checks(w)
        leak_scan(w)
        ok = True
    finally:
        for p in PROCS:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in PROCS:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()
        stop_postgres(w)
        shutil.rmtree(w.pgsock, ignore_errors=True)
        passed = sum(1 for r in RESULTS if r[1])
        log(f"{passed}/{len(RESULTS)} checks passed")
        if ok and os.environ.get("AIPASS_E2E_KEEP") != "1":
            shutil.rmtree(w.dir, ignore_errors=True)
        else:
            log(f"work directory kept: {w.dir}")
    print("E2E PASSED" if ok else "E2E FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
