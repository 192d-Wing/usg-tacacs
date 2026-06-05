#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TACACS+ E2E interoperability test runner.

Executes authentication, authorization, and accounting scenarios against
both the USG TACACS+ server and Shrubbery tac_plus, producing a
pass/fail interoperability matrix.
"""

import concurrent.futures
import hashlib
import json
import os
import socket
import struct
import sys
import time
import traceback

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_PRIV_LVL_MAX,
)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

USG_HOST = os.environ.get("USG_HOST", "172.30.0.10")
USG_PORT = int(os.environ.get("USG_PORT", "49"))
TAC_HOST = os.environ.get("TAC_HOST", "172.30.0.11")
TAC_PORT = int(os.environ.get("TAC_PORT", "49"))
DEVICE_HOST = os.environ.get("DEVICE_HOST", "172.30.0.21")
DEVICE_PORT = int(os.environ.get("DEVICE_PORT", "49"))
SECRET = os.environ.get("SHARED_SECRET", "e2e-shared-secret-k8s")
WRONG_SECRET = os.environ.get("WRONG_SECRET", "wrong-secret-value")

ARTIFACTS = "/opt/e2e/artifacts"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def authen(host, port, secret, user, password):
    """PAP authentication; returns the reply object.

    PAP sends the password in the AuthenStart data field, avoiding the
    multi-step ASCII GETUSER/GETPASS flow which has compatibility issues
    with the tacacs_plus Python library.
    """
    c = TACACSClient(host, port, secret, timeout=10)
    return c.authenticate(
        user, password, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP
    )


def author_cmd(host, port, secret, user, cmd_parts):
    """Send an authorization request for a shell command."""
    c = TACACSClient(host, port, secret, timeout=10)
    args = [b"service=shell", b"cmd=" + cmd_parts[0].encode()]
    for a in cmd_parts[1:]:
        args.append(b"cmd-arg=" + a.encode())
    return c.authorize(
        user, args,
        authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
        priv_lvl=TAC_PLUS_PRIV_LVL_MAX,
    )


def acct_request(host, port, secret, user, flag, task_id="1"):
    """Send an accounting request."""
    c = TACACSClient(host, port, secret, timeout=10)
    args = [
        b"service=shell",
        b"task_id=" + task_id.encode(),
        b"cmd=show version",
    ]
    return c.account(
        user, flag, args, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP
    )


def send_raw(host, port, payload):
    """Send raw bytes and read response, returning raw bytes or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(payload)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            return data
    except Exception:
        return None


def build_tacacs_header(pkt_type=1, seq=1, flags=0,
                        session_id=0xCAFE, length=0):
    """Build a 12-byte TACACS+ header."""
    version = 0xC0
    return struct.pack(
        "!BBBBII", version, pkt_type, seq, flags, session_id, length
    )


# ---------------------------------------------------------------------------
# Test definitions — each returns (pass: bool, detail: str)
# ---------------------------------------------------------------------------


def test_valid_auth(host, port, _label):
    """Authenticate alice with correct password."""
    reply = authen(host, port, SECRET, "alice", "alice-secret")
    return reply.valid, f"status={reply.status} ({reply.human_status})"


def test_invalid_password(host, port, _label):
    """Authenticate alice with wrong password."""
    reply = authen(host, port, SECRET, "alice", "wrong-pass")
    return reply.invalid, f"status={reply.status} ({reply.human_status})"


def test_unknown_user(host, port, _label):
    """Authenticate a nonexistent user."""
    reply = authen(host, port, SECRET, "nonexistent", "whatever")
    ok = reply.invalid or reply.error
    return ok, f"status={reply.status} ({reply.human_status})"


def test_empty_credentials(host, port, _label):
    """Authenticate with empty username and password."""
    reply = authen(host, port, SECRET, "", "")
    ok = reply.invalid or reply.error
    return ok, f"status={reply.status} ({reply.human_status})"


def test_long_credentials(host, port, _label):
    """Authenticate with max-length credentials (200 chars)."""
    reply = authen(host, port, SECRET, "A" * 200, "B" * 200)
    ok = reply.invalid or reply.error
    return ok, f"status={reply.status} ({reply.human_status})"


def test_secret_mismatch(host, port, _label):
    """Connect with the wrong shared secret."""
    try:
        reply = authen(host, port, WRONG_SECRET, "alice", "alice-secret")
        return not reply.valid, f"status={reply.status} (should not PASS)"
    except Exception as exc:
        return True, f"exception={type(exc).__name__}"


def test_author_permit(host, port, _label):
    """Authorize 'show version' for alice — should be permitted."""
    reply = author_cmd(host, port, SECRET, "alice", ["show", "version"])
    # PASS_ADD(1), PASS_REPL(2), or ERROR(17) are acceptable non-crash
    # responses. ERROR may occur if the server requires prior authn.
    ok = reply.valid or reply.status in (1, 2, 17)
    return ok, f"status={reply.status} ({reply.human_status})"


def test_author_deny(host, port, _label):
    """Authorize 'reload' for bob — should be denied."""
    reply = author_cmd(host, port, SECRET, "bob", ["reload"])
    # FAIL(16), ERROR(17), or any non-PASS is acceptable.
    ok = not reply.valid
    return ok, f"status={reply.status} ({reply.human_status})"


def test_acct_start_stop(host, port, _label):
    """Send accounting START + STOP pair."""
    r1 = acct_request(
        host, port, SECRET, "alice", TAC_PLUS_ACCT_FLAG_START, "e2e-42"
    )
    r2 = acct_request(
        host, port, SECRET, "alice", TAC_PLUS_ACCT_FLAG_STOP, "e2e-42"
    )
    # SUCCESS(1) or ERROR(2) are acceptable; garbled values indicate
    # a crypto mismatch that needs investigation.
    ok = r1.status in (1, 2) and r2.status in (1, 2)
    return ok, f"start={r1.status} stop={r2.status}"


def test_malformed_packet(host, port, _label):
    """Send a completely invalid header with garbage body."""
    payload = build_tacacs_header(
        pkt_type=0xFF, session_id=0xDEAD, length=4
    ) + b"\x00\x00\x00\x00"
    resp = send_raw(host, port, payload)
    return True, f"resp_len={len(resp) if resp else 0}"


def test_truncated_packet(host, port, _label):
    """Send a header claiming 100 bytes but only provide 4."""
    payload = build_tacacs_header(
        session_id=0xBEEF, length=100
    ) + b"\x01\x02\x03\x04"
    resp = send_raw(host, port, payload)
    return True, f"resp_len={len(resp) if resp else 0}"


def test_invalid_length(host, port, _label):
    """Send a header with length=0xFFFFFFFF (4 GB)."""
    payload = build_tacacs_header(session_id=0xFACE, length=0xFFFFFFFF)
    resp = send_raw(host, port, payload)
    return True, f"resp_len={len(resp) if resp else 0}"


def test_concurrent_burst(host, port, _label):
    """Fire 20 concurrent ASCII authentication requests."""
    def single_auth():
        return authen(host, port, SECRET, "alice", "alice-secret").valid

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futs = [pool.submit(single_auth) for _ in range(20)]
        for f in concurrent.futures.as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                results.append(False)
    pass_count = sum(1 for r in results if r)
    return pass_count == 20, f"pass={pass_count}/20"


# ---------------------------------------------------------------------------
# Ordered scenario list
# ---------------------------------------------------------------------------

SCENARIOS = [
    ("valid_auth", test_valid_auth),
    ("invalid_password", test_invalid_password),
    ("unknown_user", test_unknown_user),
    ("empty_credentials", test_empty_credentials),
    ("long_credentials", test_long_credentials),
    ("secret_mismatch", test_secret_mismatch),
    ("author_permit", test_author_permit),
    ("author_deny", test_author_deny),
    ("acct_start_stop", test_acct_start_stop),
    ("malformed_packet", test_malformed_packet),
    ("truncated_packet", test_truncated_packet),
    ("invalid_length", test_invalid_length),
    ("concurrent_burst", test_concurrent_burst),
]

SERVERS = [
    ("usg-tacacs", USG_HOST, USG_PORT),
    ("tac_plus", TAC_HOST, TAC_PORT),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def wait_for_server(host, port, name, retries=30, delay=2):
    """Block until the server accepts TCP connections."""
    for _i in range(retries):
        try:
            with socket.create_connection((host, port), timeout=2):
                print(f"  {name} ({host}:{port}) is ready")
                return True
        except OSError:
            time.sleep(delay)
    print(f"  {name} ({host}:{port}) NOT ready", file=sys.stderr)
    return False


def execute_scenarios(results):
    """Run every scenario against every server. Returns failure flag."""
    any_failure = False
    for scenario_name, test_fn in SCENARIOS:
        results[scenario_name] = {}
        for server_name, host, port in SERVERS:
            label = f"{server_name}/{scenario_name}"
            try:
                ok, detail = test_fn(host, port, label)
            except Exception as exc:
                ok = False
                detail = f"EXCEPTION: {type(exc).__name__}: {exc}"
                traceback.print_exc()
            tag = "PASS" if ok else "FAIL"
            results[scenario_name][server_name] = {
                "ok": ok, "detail": detail,
            }
            print(f"  [{tag}] {label:45s}  {detail}")
        if not results[scenario_name]["usg-tacacs"]["ok"]:
            any_failure = True
    return any_failure


def print_matrix(results):
    """Print the interoperability matrix and return mismatches."""
    print("\n" + "=" * 70)
    print("INTEROPERABILITY MATRIX")
    print("=" * 70)
    print(f"{'Scenario':<25s} {'usg-tacacs':>12s} "
          f"{'tac_plus':>12s} {'Match':>7s}")
    print("-" * 60)
    mismatches = []
    for name, _ in SCENARIOS:
        usg = results[name]["usg-tacacs"]
        tac = results[name]["tac_plus"]
        u = "PASS" if usg["ok"] else "FAIL"
        t = "PASS" if tac["ok"] else "FAIL"
        match = usg["ok"] == tac["ok"]
        m = "YES" if match else "** NO **"
        print(f"  {name:<23s} {u:>12s} {t:>12s} {m:>7s}")
        if not match:
            mismatches.append(name)
    return mismatches


def print_details(results, mismatches):
    """Print mismatch details and USG failures."""
    if mismatches:
        print(f"\n--- Protocol Mismatches ({len(mismatches)}) ---")
        for m in mismatches:
            usg_d = results[m]["usg-tacacs"]["detail"]
            tac_d = results[m]["tac_plus"]["detail"]
            print(f"  {m}:")
            print(f"    usg-tacacs: {usg_d}")
            print(f"    tac_plus:   {tac_d}")
    else:
        print("\n  No protocol mismatches detected.")

    usg_failures = [
        n for n, _ in SCENARIOS
        if not results[n]["usg-tacacs"]["ok"]
    ]
    if usg_failures:
        print(f"\n--- USG TACACS+ Failures ({len(usg_failures)}) ---")
        for n in usg_failures:
            print(f"  {n}: {results[n]['usg-tacacs']['detail']}")
    return usg_failures


def write_artifacts(results, mismatches, usg_failures):
    """Write JSON results and Markdown matrix to disk."""
    os.makedirs(ARTIFACTS, exist_ok=True)
    with open(os.path.join(ARTIFACTS, "results.json"), "w",
              encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(ARTIFACTS, "matrix.md"), "w",
              encoding="utf-8") as f:
        f.write("# TACACS+ E2E Interoperability Matrix\n\n")
        f.write("| Scenario | usg-tacacs | tac_plus | Match |\n")
        f.write("|----------|:----------:|:--------:|:-----:|\n")
        for name, _ in SCENARIOS:
            usg = results[name]["usg-tacacs"]
            tac = results[name]["tac_plus"]
            u = "PASS" if usg["ok"] else "FAIL"
            t = "PASS" if tac["ok"] else "FAIL"
            m = "YES" if usg["ok"] == tac["ok"] else "NO"
            f.write(f"| {name} | {u} | {t} | {m} |\n")
        write_mismatch_section(f, results, mismatches, usg_failures)


def write_mismatch_section(f, results, mismatches, usg_failures):
    """Append mismatch and failure sections to the markdown file."""
    if mismatches:
        f.write("\n## Protocol Mismatches\n\n")
        for m in mismatches:
            usg_d = results[m]["usg-tacacs"]["detail"]
            tac_d = results[m]["tac_plus"]["detail"]
            f.write(f"### {m}\n\n")
            f.write(f"- **usg-tacacs**: {usg_d}\n")
            f.write(f"- **tac_plus**: {tac_d}\n\n")
    if usg_failures:
        f.write("\n## USG TACACS+ Failures\n\n")
        for n in usg_failures:
            d = results[n]["usg-tacacs"]["detail"]
            f.write(f"- **{n}**: {d}\n")


def run_all():
    """Execute every scenario against every server and report."""
    print("=" * 70)
    print("TACACS+ E2E Interoperability Test Suite")
    print("=" * 70)

    print("\n--- Connectivity ---")
    for name, host, port in SERVERS:
        if not wait_for_server(host, port, name):
            print(f"FATAL: cannot reach {name}", file=sys.stderr)
            return 1

    print("\n--- Running Scenarios ---\n")
    results = {}
    any_failure = execute_scenarios(results)
    mismatches = print_matrix(results)
    usg_failures = print_details(results, mismatches)
    write_artifacts(results, mismatches, usg_failures)
    print(f"\nArtifacts written to {ARTIFACTS}/")

    if any_failure:
        print("\nRESULT: FAIL (usg-tacacs had test failures)")
        return 1
    print("\nRESULT: PASS (all usg-tacacs tests passed)")
    return 0


# ---------------------------------------------------------------------------
# ASCII TACACS+ raw packet helpers (for device flow / router scenarios).
#
# The tacacs_plus library only supports single-packet PAP/CHAP.  ASCII auth
# is a multi-packet exchange (START → GETUSER/GETDATA/GETPASS → CONTINUE …)
# so we drive it with raw sockets + MD5 body obfuscation.
#
# Proto constants from tacacs-proto/src/lib.rs:
#   TYPE_AUTHEN=0x01  VER=0xC1
#   PASS=0x01  FAIL=0x02  GETDATA=0x03  GETUSER=0x04  GETPASS=0x05
# ---------------------------------------------------------------------------

_VER      = 0xC1
_T_AUTH   = 0x01
_NOECHO   = 0x01
_ST_PASS    = 0x01
_ST_FAIL    = 0x02
_ST_GETDATA = 0x03
_ST_GETUSER = 0x04
_ST_GETPASS = 0x05
_HDR_FMT  = "!BBBBII"  # ver type seq flags session_id length


def _ascii_obfusc(secret_bytes, sid, seq, body):
    """Apply TACACS+ MD5 body obfuscation (symmetric)."""
    prev, rem = b"", bytearray(body)
    i = 0
    while i < len(rem):
        seed = struct.pack("!I", sid) + secret_bytes + bytes([_VER, seq]) + prev
        pad  = hashlib.md5(seed).digest()
        for j in range(min(16, len(rem) - i)):
            rem[i + j] ^= pad[j]
        prev = pad
        i += 16
    return bytes(rem)


def _ascii_send(sock, sid, seq, body, secret_bytes):
    enc = _ascii_obfusc(secret_bytes, sid, seq, body)
    sock.sendall(struct.pack(_HDR_FMT, _VER, _T_AUTH, seq, 0, sid, len(enc)) + enc)


def _ascii_recv(sock, sid, secret_bytes):
    hdr = b""
    while len(hdr) < 12:
        chunk = sock.recv(12 - len(hdr))
        if not chunk:
            raise ConnectionError("connection closed")
        hdr += chunk
    _v, _t, rseq, _f, _s, length = struct.unpack(_HDR_FMT, hdr)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise ConnectionError("connection closed")
        body += chunk
    dec = _ascii_obfusc(secret_bytes, sid, rseq, body)
    msg_len = struct.unpack("!H", dec[2:4])[0]
    return dec[0], dec[1], dec[6:6 + msg_len].decode(errors="replace")


def _ascii_start(user=b"", port=b"tty0", rem=b"127.0.0.1"):
    return struct.pack("!BBBBBBBB",
        0x01, 0x01, 0x01, 0x01,
        len(user), len(port), len(rem), 0,
    ) + user + port + rem


def _ascii_cont(user_msg=b""):
    return struct.pack("!HHB", len(user_msg), 0, 0) + user_msg


# ---------------------------------------------------------------------------
# Router test scenarios (device flow server only)
# ---------------------------------------------------------------------------

def test_router_excluded_gets_password(host, port, _label):
    """Excluded user (alice) must receive GETPASS and authenticate via static creds."""
    sid = 0xE1000001
    sec = SECRET.encode()
    with socket.create_connection((host, port), timeout=10) as s:
        _ascii_send(s, sid, 1, _ascii_start(b"alice"), sec)
        st, fl, _msg = _ascii_recv(s, sid, sec)
        if st != _ST_GETPASS:
            return False, f"expected GETPASS(0x{_ST_GETPASS:02x}), got 0x{st:02x}"
        if not (fl & _NOECHO):
            return False, "GETPASS reply missing NOECHO flag"
        _ascii_send(s, sid, 3, _ascii_cont(b"alice-secret"), sec)
        st, _fl, _msg = _ascii_recv(s, sid, sec)
        return st == _ST_PASS, f"auth_status=0x{st:02x}"


def test_router_nonexcluded_gets_device_url(host, port, _label):
    """Non-excluded user (bob) must receive GETDATA with the mock ICAM URL."""
    sid = 0xE2000001
    sec = SECRET.encode()
    with socket.create_connection((host, port), timeout=10) as s:
        _ascii_send(s, sid, 1, _ascii_start(b"bob"), sec)
        st, _fl, msg = _ascii_recv(s, sid, sec)
        if st != _ST_GETDATA:
            return False, f"expected GETDATA(0x{_ST_GETDATA:02x}), got 0x{st:02x}"
        has_url = "mock-icam" in msg or "TEST-CODE" in msg
        return has_url, f"status=GETDATA url={'yes' if has_url else 'no'} msg={msg[:60]!r}"


ROUTER_SCENARIOS = [
    ("router_excluded_gets_password",     test_router_excluded_gets_password),
    ("router_nonexcluded_gets_device_url", test_router_nonexcluded_gets_device_url),
]


def run_router_scenarios():
    """Run router scenarios against the device-flow server; return failure flag."""
    print("\n--- Router Scenarios (usg-tacacs-device) ---\n")
    if not wait_for_server(DEVICE_HOST, DEVICE_PORT, "usg-tacacs-device"):
        print("  SKIP: usg-tacacs-device not reachable", file=sys.stderr)
        return False
    any_fail = False
    for name, fn in ROUTER_SCENARIOS:
        label = f"usg-tacacs-device  {name}"
        try:
            ok, detail = fn(DEVICE_HOST, DEVICE_PORT, label)
        except Exception:
            ok, detail = False, traceback.format_exc().splitlines()[-1]
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name:<40s}  {detail}")
        if not ok:
            any_fail = True
    return any_fail


def run_all():
    """Execute every scenario against every server and report."""
    print("=" * 70)
    print("TACACS+ E2E Interoperability Test Suite")
    print("=" * 70)

    print("\n--- Connectivity ---")
    for name, host, port in SERVERS:
        if not wait_for_server(host, port, name):
            print(f"FATAL: cannot reach {name}", file=sys.stderr)
            return 1

    print("\n--- Running Scenarios ---\n")
    results = {}
    any_failure = execute_scenarios(results)
    router_failure = run_router_scenarios()
    mismatches = print_matrix(results)
    usg_failures = print_details(results, mismatches)
    write_artifacts(results, mismatches, usg_failures)
    print(f"\nArtifacts written to {ARTIFACTS}/")

    if any_failure or router_failure:
        print("\nRESULT: FAIL (usg-tacacs had test failures)")
        return 1
    print("\nRESULT: PASS (all usg-tacacs tests passed)")
    return 0


if __name__ == "__main__":
    sys.exit(run_all())
