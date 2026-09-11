#!/usr/bin/env python3
"""
CrimeNet end-to-end test against a running local stack.

Drives the real API with real Keycloak tokens for each demo role, and checks the database
directly where the API alone cannot prove a property (encryption at rest, append-only
enforcement, rows that must survive a rollback).

Prerequisites: `docker compose up -d` and the backend running on :8080 with the dev profile.
Standard library only.

    python scripts/e2e_smoke_test.py

Point it elsewhere with CRIMENET_API (default http://localhost:8080) and
CRIMENET_PG_CONTAINER (default crimenet-postgres).

It creates test data (a case, evidence, documents, a share) in the local database. It
temporarily disables one append-only trigger to simulate a DBA tampering with a custody
record, and restores both the trigger and the row before exiting.
"""

import datetime
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

API = __import__("os").environ.get("CRIMENET_API", "http://localhost:8080")
KEYCLOAK = "http://localhost:8180/realms/crimenet/protocol/openid-connect/token"
CLIENT_ID = "crimenet-frontend"
PG = ["docker", "exec", "-i", __import__("os").environ.get("CRIMENET_PG_CONTAINER", "crimenet-postgres"), "psql", "-U", "crimenet", "-d", "crimenet",
      "-t", "-A", "-v", "ON_ERROR_STOP=1"]

USERS = {
    "admin": "admin123",
    "inspector1": "inspector123",
    "supervisor1": "supervisor123",
    "forensic1": "forensic123",
    "prosecutor1": "prosecutor123",
    "auditor1": "auditor123",
}

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*").encode("ascii")

results = []  # (group, name, passed, detail)


# ── plumbing ──────────────────────────────────────────────────────────────────

def check(group, name, passed, detail=""):
    results.append((group, name, bool(passed), detail))
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail and not passed else ""))
    return passed


def request(method, path, token=None, body=None, headers=None, raw=None, content_type=None):
    url = path if path.startswith("http") else API + path
    data = None
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    if raw is not None:
        data = raw
        if content_type:
            h["Content-Type"] = content_type
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read()
            return resp.status, dict(resp.headers), payload
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def jbody(payload):
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def multipart(fields, file_field, filename, file_bytes, file_type):
    boundary = "----crimenet" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    parts.append(
        (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{filename}\"\r\n"
         f"Content-Type: {file_type}\r\n\r\n").encode() + file_bytes + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def sql(query):
    out = subprocess.run(PG, input=query.encode(), capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.decode(errors="replace").strip())
    return out.stdout.decode().strip()


def token_for(username):
    form = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "username": username,
        "password": USERS[username], "grant_type": "password",
    }).encode()
    req = urllib.request.Request(KEYCLOAK, data=form, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


def small_pdf(text):
    # A minimal, valid single-page PDF carrying `text`.
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return out


# ── tests ─────────────────────────────────────────────────────────────────────

def main():
    run_id = uuid.uuid4().hex[:8]
    print(f"CrimeNet end-to-end test — run {run_id}\n")

    # ── Identity ──
    print("Identity")
    tokens, ids = {}, {}
    for u in USERS:
        try:
            tokens[u] = token_for(u)
            s, _, b = request("GET", "/api/v1/users/me", tokens[u])
            ids[u] = jbody(b).get("data", {}).get("id")
            check("Identity", f"{u} authenticates and is provisioned", s == 200 and ids[u], f"HTTP {s}")
        except Exception as e:
            check("Identity", f"{u} authenticates", False, str(e))
    if len(ids) < len(USERS) or not all(ids.values()):
        print("\nCannot continue without every demo user.")
        return summarise()

    insp, sup, foren, pros, aud, adm = (tokens[k] for k in
                                         ("inspector1", "supervisor1", "forensic1", "prosecutor1", "auditor1", "admin"))

    # ── Platform ──
    print("\nPlatform and transport")
    s, _, b = request("GET", "/actuator/health")
    check("Platform", "health is public and UP", s == 200 and jbody(b).get("status") == "UP", f"HTTP {s}")
    s, _, b = request("GET", "/actuator/health/readiness")
    check("Platform", "readiness UP (database and MinIO)", s == 200 and jbody(b).get("status") == "UP", f"HTTP {s}")
    s, h, _ = request("GET", "/")
    check("Platform", "portal is served", s == 200, f"HTTP {s}")
    hl = {k.lower(): v for k, v in h.items()}
    check("Platform", "Content-Security-Policy is set", "content-security-policy" in hl)
    check("Platform", "X-Frame-Options: DENY", hl.get("x-frame-options", "").upper() == "DENY")
    check("Platform", "X-Content-Type-Options: nosniff", hl.get("x-content-type-options", "") == "nosniff")
    s, _, _ = request("GET", "/api/v1/cases")
    check("Platform", "API without a token is 401", s == 401, f"HTTP {s}")
    s, _, _ = request("GET", "/api/v1/cases", token="not-a-real-token")
    check("Platform", "API with a forged token is 401", s == 401, f"HTTP {s}")

    # ── Error mapping ──
    print("\nError mapping (these were all 500s)")
    s, _, _ = request("POST", "/api/v1/cases", insp, raw=b"{not json", content_type="application/json")
    check("Errors", "malformed JSON is 400", s == 400, f"HTTP {s}")
    s, _, _ = request("GET", "/api/v1/cases/not-a-uuid", insp)
    check("Errors", "malformed UUID in path is 400", s == 400, f"HTTP {s}")
    s, _, _ = request("DELETE", "/api/v1/cases", insp)
    check("Errors", "unsupported verb is 405", s == 405, f"HTTP {s}")
    s, _, _ = request("GET", f"/api/v1/cases/{uuid.uuid4()}", adm)
    check("Errors", "nonexistent case is 404, not allowed", s == 404, f"HTTP {s}")

    # ── Cases ──
    print("\nCases and identifiers")
    s, _, b = request("POST", "/api/v1/cases", insp, {"title": f"E2E case {run_id}", "description": "End-to-end test"})
    case = jbody(b).get("data", {})
    case_id = case.get("id")
    check("Cases", "investigator creates a case", s == 201 and case_id, f"HTTP {s} {b[:200]!r}")
    cn = case.get("caseNumber", "")
    check("Cases", "case number comes from the sequence", cn.startswith("CASE-") and cn[-6:].isdigit(), cn)
    s2, _, b2 = request("POST", "/api/v1/cases", insp, {"title": f"E2E case {run_id} second"})
    cn2 = jbody(b2).get("data", {}).get("caseNumber", "")
    check("Cases", "consecutive cases get distinct numbers", s2 == 201 and cn2 and cn2 != cn, f"{cn} / {cn2}")
    s, _, _ = request("GET", f"/api/v1/cases/{case_id}", insp)
    check("Cases", "creator can read the case", s == 200, f"HTTP {s}")
    s, _, _ = request("GET", f"/api/v1/cases/{case_id}", foren)
    check("Cases", "unassigned officer is refused", s == 403, f"HTTP {s}")

    # ── Victim and witness PII ──
    print("\nVictim/witness PII (encryption at rest, RLS)")
    aadhaar = f"9812 4521 {run_id[:4]}"
    s, _, b = request("POST", f"/api/v1/cases/{case_id}/persons", insp, {
        "personName": "E2E Witness", "roleType": "WITNESS", "idType": "AADHAAR",
        "idNumber": aadhaar, "contact": "+91 98765 43210", "address": "12 Test Marg, Lucknow"})
    person_id = jbody(b).get("data", {}).get("id")
    check("PII", "investigator adds a witness", s in (200, 201) and person_id, f"HTTP {s} {b[:200]!r}")
    s, _, b = request("GET", f"/api/v1/cases/{case_id}/persons", insp)
    people = jbody(b).get("data", []) or []
    check("PII", "assigned investigator reads it back decrypted",
          s == 200 and any(p.get("idNumber") == aadhaar for p in people), f"HTTP {s}")
    if person_id:
        stored = sql(f"SELECT id_number_encrypted FROM case_person WHERE id = '{person_id}';")
        check("PII", "stored value is ciphertext, not the Aadhaar",
              stored.startswith("enc:v1:") and aadhaar not in stored, stored[:24] + "…")
    s, _, b = request("GET", f"/api/v1/cases/{case_id}/persons", foren)
    visible = jbody(b).get("data", []) or [] if s == 200 else []
    check("PII", "unassigned officer sees no witnesses", s in (403, 404) or len(visible) == 0,
          f"HTTP {s}, {len(visible)} rows")

    # ── Evidence and custody ──
    print("\nEvidence and chain of custody")
    s, _, b = request("POST", "/api/v1/evidence", insp, {
        "caseId": case_id, "title": "Seized laptop", "description": "E2E exhibit",
        "source": "Search and seizure", "sourceDevice": "Dell Latitude 7420",
        "location": "14 MG Road, Kanpur", "initialHash": "ab" * 32})
    ev = jbody(b).get("data", {})
    ev_id = ev.get("id")
    check("Custody", "evidence registered", s in (200, 201) and ev_id, f"HTTP {s} {b[:200]!r}")
    code = ev.get("evidenceCode", "")
    check("Custody", "exhibit code comes from the sequence", code.startswith("E-") and code[2:].isdigit(), code)

    s, _, b = request("GET", f"/api/v1/evidence/{ev_id}/chain", insp)
    chain = jbody(b).get("data", []) or []
    head = chain[-1]["id"] if chain else None
    check("Custody", "chain starts with REGISTERED", s == 200 and chain and chain[0].get("action") == "REGISTERED")

    s, _, b = request("POST", f"/api/v1/evidence/{ev_id}/custody", foren, {
        "toActorId": ids["supervisor1"], "action": "TRANSFERRED", "purpose": "x",
        "location": "x", "previousEventId": head})
    check("Custody", "non-custodian cannot transfer", s == 403, f"HTTP {s}")

    s, _, b = request("POST", f"/api/v1/evidence/{ev_id}/custody", insp, {
        "toActorId": ids["supervisor1"], "action": "TRANSFERRED", "purpose": "Forensic imaging",
        "location": "FSL Lucknow", "notes": "Sealed bag 4", "previousEventId": str(uuid.uuid4())})
    check("Custody", "stale previousEventId is rejected (409)", s == 409, f"HTTP {s}")

    s, _, b = request("POST", f"/api/v1/evidence/{ev_id}/custody", insp, {
        "toActorId": ids["supervisor1"], "action": "TRANSFERRED", "purpose": "Forensic imaging",
        "location": "FSL Lucknow", "notes": "Sealed bag 4, tamper strip intact", "previousEventId": head})
    transfer_id = jbody(b).get("data", {}).get("id")
    check("Custody", "custodian transfers to supervisor", s in (200, 201) and transfer_id, f"HTTP {s} {b[:200]!r}")

    s, _, b = request("GET", f"/api/v1/evidence/{ev_id}/chain/verify", insp)
    v = jbody(b).get("data", {})
    check("Custody", "chain verifies intact", s == 200 and v.get("intact") is True and v.get("linksChecked") == 2,
          json.dumps(v)[:200])
    check("Custody", "new links use the full-field hash (not legacy)",
          all(not l.get("legacy") for l in v.get("links", [])))

    # The DBA attack: disable the append-only trigger and rewrite the seizure location.
    try:
        blocked = False
        try:
            sql(f"UPDATE custody_event SET location = 'x' WHERE id = '{transfer_id}';")
        except RuntimeError as e:
            blocked = "append-only" in str(e)
        check("Custody", "append-only trigger blocks rewriting custody", blocked)

        original = sql(f"SELECT location FROM custody_event WHERE id = '{transfer_id}';")
        sql("ALTER TABLE custody_event DISABLE TRIGGER custody_event_no_update;"
            f"UPDATE custody_event SET location = 'Somewhere else entirely' WHERE id = '{transfer_id}';"
            "ALTER TABLE custody_event ENABLE TRIGGER custody_event_no_update;")
        s, _, b = request("GET", f"/api/v1/evidence/{ev_id}/chain/verify", insp)
        v = jbody(b).get("data", {})
        check("Custody", "rewritten location is detected (was invisible before)", v.get("intact") is False,
              json.dumps(v)[:200])
    finally:
        sql("ALTER TABLE custody_event DISABLE TRIGGER custody_event_no_update;"
            f"UPDATE custody_event SET location = 'FSL Lucknow' WHERE id = '{transfer_id}';"
            "ALTER TABLE custody_event ENABLE TRIGGER custody_event_no_update;")
    s, _, b = request("GET", f"/api/v1/evidence/{ev_id}/chain/verify", insp)
    check("Custody", "restoring the row restores verification", jbody(b).get("data", {}).get("intact") is True)

    # ── §65B certificate ──
    print("\nSection 65B certificate")
    s, h, b = request("GET", f"/api/v1/evidence/{ev_id}/bsa-certificate", insp)
    check("65B", "assigned officer gets a PDF", s == 200 and b[:4] == b"%PDF", f"HTTP {s}")
    s, _, _ = request("GET", f"/api/v1/evidence/{ev_id}/bsa-certificate", foren)
    check("65B", "unassigned officer is refused (was an open IDOR)", s == 403, f"HTTP {s}")
    audited = sql("SELECT count(*) FROM audit_event WHERE event_type = 'BSA_65B_CERTIFICATE_GENERATED' "
                  f"AND resource_id = '{ev_id}';")
    check("65B", "certificate generation is audited", audited not in ("", "0"), audited)

    # ── Documents and malware scanning ──
    print("\nDocuments and malware scanning")
    pdf = small_pdf(f"FIR statement {run_id}")
    body, ctype = multipart({"docType": "FIR", "title": f"FIR {run_id}"}, "file", f"fir-{run_id}.pdf", pdf,
                            "application/pdf")
    s, _, b = request("POST", f"/api/v1/cases/{case_id}/documents", insp, raw=body, content_type=ctype)
    doc_id = jbody(b).get("data", {}).get("id")
    check("Documents", "clean PDF uploads", s in (200, 201) and doc_id, f"HTTP {s} {b[:200]!r}")

    body, ctype = multipart({"docType": "REPORT"}, "file", "quarterly-report.pdf", EICAR, "application/pdf")
    s, _, b = request("POST", f"/api/v1/cases/{case_id}/documents", insp, raw=body, content_type=ctype)
    check("Documents", "EICAR renamed as a PDF is rejected (422)", s == 422, f"HTTP {s} {b[:160]!r}")

    body, ctype = multipart({"docType": "PHOTO"}, "file", "scene.png", b"MZ\x90\x00" + b"\x00" * 60, "image/png")
    s, _, b = request("POST", f"/api/v1/cases/{case_id}/documents", insp, raw=body, content_type=ctype)
    check("Documents", "executable disguised as PNG is rejected", s == 422, f"HTTP {s} {b[:160]!r}")

    rejected = sql("SELECT count(*) FROM audit_event WHERE event_type = 'MALWARE_DETECTED' "
                   f"AND case_id = '{case_id}';")
    check("Documents", "rejections leave a durable audit record", rejected not in ("", "0"), rejected)

    if doc_id:
        s, _, b = request("GET", f"/api/v1/documents/{doc_id}/integrity", insp)
        check("Documents", "integrity check recomputes and matches", s == 200 and jbody(b).get("data", {}).get("valid"),
              f"HTTP {s} {b[:200]!r}")
        s, _, b = request("GET", f"/api/v1/documents/{doc_id}/download", insp)
        url = jbody(b).get("data", "") or ""
        check("Documents", "download URL forces attachment disposition",
              s == 200 and "response-content-disposition=attachment" in url, url[:120])

        body, ctype = multipart({"docType": "FIR"}, "file", f"copy-{run_id}.pdf", pdf, "application/pdf")
        s, _, b = request("POST", f"/api/v1/cases/{case_id}/documents", insp, raw=body, content_type=ctype)
        dup_id = jbody(b).get("data", {}).get("id")
        if s in (200, 201) and dup_id:
            k1 = sql(f"SELECT object_key FROM document_version WHERE document_id = '{doc_id}';")
            k2 = sql(f"SELECT object_key FROM document_version WHERE document_id = '{dup_id}';")
            check("Documents", "identical bytes in the same org reuse the stored object", k1 == k2, f"{k1} / {k2}")
        else:
            check("Documents", "duplicate upload succeeds", False, f"HTTP {s}")

    s, _, b = request("GET", f"/api/v1/cases/{case_id}/documents", foren)
    check("Documents", "unassigned officer cannot list documents", s == 403, f"HTTP {s}")

    # ── OCR (added upstream) ──
    print("\nOCR endpoint")
    body, ctype = multipart({"filterMode": "AUTO_ENHANCE"}, "file", "fir.pdf", pdf, "application/pdf")
    s, _, b = request("POST", "/api/v1/documents/ocr", insp, raw=body, content_type=ctype)
    check("OCR", "extracts from an uploaded PDF", s == 200, f"HTTP {s} {b[:200]!r}")
    s, _, _ = request("POST", "/api/v1/documents/ocr", None, raw=body, content_type=ctype)
    check("OCR", "requires authentication", s == 401, f"HTTP {s}")

    # ── Sharing ──
    print("\nSharing")
    in_week = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    s, _, b = request("POST", "/api/v1/shares", insp, {
        "caseId": case_id, "recipientId": ids["prosecutor1"], "purpose": "Charge sheet review",
        "scope": [], "rights": "VIEW_ONLY", "expiresAt": in_week})
    check("Sharing", "empty scope is refused (was allow-all)", s in (400, 422), f"HTTP {s}")
    s, _, b = request("POST", "/api/v1/shares", insp, {
        "caseId": case_id, "recipientId": ids["prosecutor1"], "purpose": "Charge sheet review",
        "scope": [doc_id] if doc_id else ["FIR"], "rights": "DOWNLOAD", "expiresAt": "3000-01-01T00:00:00Z"})
    share = jbody(b).get("data", {})
    share_id = share.get("id")
    check("Sharing", "share with explicit scope is created", s == 201 and share_id, f"HTTP {s} {b[:200]!r}")
    exp = share.get("expiresAt", "")
    check("Sharing", "year-3000 expiry is clamped to the ceiling", exp[:4] not in ("", "3000"), exp)
    check("Sharing", "step-up is enforced by policy, not the caller", share.get("mfaRequired") is True)

    if share_id and doc_id:
        ver = sql(f"SELECT current_version_id FROM document WHERE id = '{doc_id}';")
        s, _, b = request("GET", f"/api/v1/shares/{share_id}/download/{ver}", pros)
        d = jbody(b).get("data", {})
        check("Sharing", "recipient downloads within scope", s == 200 and d.get("downloadUrl"), f"HTTP {s} {b[:200]!r}")
        check("Sharing", "response no longer claims a watermark it never applied", d.get("watermark") is False)
        rows = sql(f"SELECT count(*) FROM share_access WHERE share_package_id = '{share_id}';")
        check("Sharing", "download is recorded in share_access (was silently discarded)", rows not in ("", "0"), rows)

    # ── Break-glass ──
    print("\nBreak-glass emergency access")
    s, _, b = request("POST", "/api/v1/break-glass", foren, {"caseId": case_id, "reason": "short"})
    check("BreakGlass", "too-short justification is refused", s in (400, 422), f"HTTP {s}")
    s, _, b = request("POST", "/api/v1/break-glass", foren,
                      {"caseId": case_id, "reason": "Suspect device must be imaged before remote wipe"})
    grant_id = jbody(b).get("data", {}).get("id")
    check("BreakGlass", "forensic officer obtains a grant (dev step-up bypass)", s == 200 and grant_id,
          f"HTTP {s} {b[:200]!r}")
    s, _, _ = request("GET", f"/api/v1/cases/{case_id}", foren)
    check("BreakGlass", "grant opens the case to the grantee", s == 200, f"HTTP {s}")
    if grant_id:
        s, _, _ = request("DELETE", f"/api/v1/break-glass/{grant_id}", pros)
        check("BreakGlass", "unrelated user cannot revoke someone else's grant", s == 403, f"HTTP {s}")
        s, _, _ = request("DELETE", f"/api/v1/break-glass/{grant_id}", foren)
        check("BreakGlass", "grantee can revoke their own grant", s == 200, f"HTTP {s}")
    denied = sql("SELECT count(*) FROM security_event WHERE event_type = 'BREAK_GLASS_REVOKE_FORBIDDEN';")
    check("BreakGlass", "the refused revocation is in the security-event trail", denied not in ("", "0"), denied)

    # ── Audit ──
    print("\nAudit trail")
    s, _, b = request("GET", "/api/v1/audit?size=5", aud)
    check("Audit", "auditor lists events", s == 200 and jbody(b).get("data", {}).get("content"), f"HTTP {s}")
    s, _, b = request("GET", "/api/v1/audit?size=100000", aud)
    size = jbody(b).get("data", {}).get("size", 0)
    check("Audit", "page size is capped", s == 200 and 0 < size <= 200, f"size={size}")
    s, _, _ = request("GET", "/api/v1/audit", insp)
    check("Audit", "investigator cannot read the audit trail", s == 403, f"HTTP {s}")
    s, _, b = request("GET", "/api/v1/audit/verify-chain?limit=2000", aud)
    v = jbody(b).get("data", {})
    check("Audit", "audit chain verifies intact", s == 200 and v.get("intact") is True, json.dumps(v)[:300])
    unscoped = sql("SELECT count(*) FROM audit_event WHERE org_id IS NULL "
                   f"AND created_at > now() - interval '10 minutes' AND case_id = '{case_id}';")
    check("Audit", "new events carry org_id", unscoped == "0", f"{unscoped} unscoped")

    # ── Provenance ──
    print("\nProvenance")
    s, _, _ = request("POST", "/api/v1/provenance/anchor", insp)
    check("Provenance", "investigator cannot trigger anchoring (spends gas)", s == 403, f"HTTP {s}")
    frozen = False
    try:
        sql("UPDATE merkle_batch SET merkle_root = 'x' WHERE batch_number = (SELECT min(batch_number) FROM merkle_batch);")
        frozen = sql("SELECT count(*) FROM merkle_batch;") == "0"  # nothing to update is also safe
    except RuntimeError as e:
        frozen = "immutable" in str(e)
    check("Provenance", "anchored Merkle roots cannot be rewritten", frozen)

    # ── Account status ──
    print("\nAccount status")
    try:
        sql(f"UPDATE app_user SET status = 'SUSPENDED' WHERE id = '{ids['prosecutor1']}';")
        s, _, _ = request("GET", "/api/v1/users/me", pros)
        check("Status", "suspended officer is refused despite a valid token", s == 403, f"HTTP {s}")
    finally:
        sql(f"UPDATE app_user SET status = 'ACTIVE' WHERE id = '{ids['prosecutor1']}';")
    s, _, _ = request("GET", "/api/v1/users/me", pros)
    check("Status", "reactivated officer regains access", s == 200, f"HTTP {s}")

    return summarise()


def summarise():
    passed = sum(1 for r in results if r[2])
    failed = [r for r in results if not r[2]]
    print("\n" + "=" * 72)
    print(f"{passed}/{len(results)} passed" + (f", {len(failed)} FAILED" if failed else ""))
    for g, n, _, d in failed:
        print(f"  FAIL [{g}] {n}  — {d}")
    print("=" * 72)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
