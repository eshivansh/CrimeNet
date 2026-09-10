# CrimeNet — Secure Digital Evidence & Document Management System Demo Runbook

Everything needed to get the system up and walk through the official government portal.

---

## 1. Prerequisites

| Requirement | Check |
|---|---|
| Java 21 JDK | `java -version` |
| Docker Desktop running | whale icon steady in the tray |

The Maven wrapper (`backend/mvnw.cmd`) is included — no separate Maven install is needed.

---

## 2. Start everything

From the repository root:

```powershell
.\start-demo.ps1
```

That script brings up the seven containers, waits until each reports healthy, builds the
backend, and runs it. The first run pulls several GB of images and takes a few minutes;
later runs start in well under a minute.

Then open **<http://localhost:8080>**.

Useful variations:

```powershell
.\start-demo.ps1 -SkipBuild    # reuse the existing jar
.\start-demo.ps1 -InfraOnly    # containers only
```

To do it by hand instead:

```powershell
docker compose up -d
cd backend
.\mvnw.cmd clean package -DskipTests
java -jar target\nyayavault-backend-0.1.0-SNAPSHOT.jar --spring.profiles.active=dev
```

### Endpoints

| Surface | URL | Credentials |
|---|---|---|
| **Demo console** | <http://localhost:8080> | pick a user in the UI |
| Swagger UI | <http://localhost:8080/swagger-ui.html> | — |
| Keycloak admin | <http://localhost:8180> | `admin` / `admin` |
| MinIO console | <http://localhost:9001> | `minioadmin` / `minioadmin123` |
| RabbitMQ | <http://localhost:15672> | `nyayavault` / `nyayavault_dev` |

### Demo accounts

| User | Password | Role |
|---|---|---|
| `inspector1` | `inspector123` | INVESTIGATOR |
| `supervisor1` | `supervisor123` | SUPERVISOR |
| `forensic1` | `forensic123` | FORENSIC_OFFICER |
| `prosecutor1` | `prosecutor123` | PROSECUTOR |
| `auditor1` | `auditor123` | AUDITOR |
| `admin` | `admin123` | ADMIN |

Shut down with `docker compose down` (add `-v` to also wipe the data volumes and start fresh).

---

## 3. The demo script

The console is laid out as eight numbered steps in the order you should present them.
The right-hand **API console** echoes every request and response — keep it visible, it is
what convinces a technical judge that the UI is not faking anything.

### Before the judges arrive

1. Sign in as `inspector1`.
2. Click **Provision all demo users** once. This signs in as each demo account so they
   exist as internal users and can be chosen as a custody-transfer target.
3. Sign back in as `inspector1`.
4. Have a small PDF or JPEG ready to upload.

### Step 1 — Identity

Sign in as `inspector1`. Point out that the roles shown come from the Keycloak JWT's
`realm_access.roles`, and that the internal user record was auto-provisioned from the
token's subject claim on first call.

> "Authentication is Keycloak. But authorization is never decided from the token alone —
> that is the next part."

### Step 2 — Create a case

Create the case. The creator is auto-assigned as `LEAD_INVESTIGATOR`.

> "Access to this case is now checked against a live database assignment on every request.
> A valid token for the wrong officer is not enough."

### Step 3 — Victims and witnesses (row-level security)

Add a victim and a witness to the case, then click **Why can I see this?**

Now sign in as `supervisor1` — a real officer with a senior role, but not assigned to this
case — and look again. The list is empty, and the panel says why.

> "Nothing on this page filtered that. The application asked PostgreSQL for the rows on
> this case and PostgreSQL returned none, because the policy on that table matches only
> officers holding a live assignment. If my application code had a bug and forgot to check,
> the answer would still be zero rows."

Sign back in as `inspector1` and the rows return. This is the strongest security moment in
the demo, because the enforcement is visibly *below* the application.

Two details worth having ready if a technical judge presses:

- PostgreSQL exempts a table's **owner** from its own policies. So the table is set to
  `FORCE ROW LEVEL SECURITY` **and** the application connects as a restricted role
  (`nyayavault_app`) holding neither SUPERUSER nor BYPASSRLS. Connecting as the superuser
  owner silently disables every policy — a genuine trap, and one this project hit.
- The acting officer is bound per transaction via `set_config('app.current_user_id', ...)`.
  If that binding is ever missing, the policy matches nothing — it fails closed.

### Step 4 — Upload and verify a document

Upload the file. Then click **Verify integrity**.

The verification panel shows the stored SHA-256 next to a digest recomputed from the object
actually sitting in MinIO right now.

> "Upload lands in a quarantine bucket first, gets malware-scanned, hashed and
> content-deduplicated, and is only then committed to the documents bucket — through an
> outbox pattern, so the database row and the object can never disagree."

Now the part that earns belief. A check a judge has only ever seen pass proves nothing —
they cannot tell it from a hard-coded tick. So show it fail.

Click **Simulate tampering**. It rewrites eight bytes of the stored file *directly in object
storage*, leaving the database untouched — exactly what an insider with storage access could
do. Then click **Verify integrity** again:

```
✗ INTEGRITY FAILURE — the stored object no longer matches its recorded hash.
stored     = 904189421cc7734bb07e24321057dad8…
recomputed = 7251c42e07104861e52432d63eef97ee…
```

> "Same document, same endpoint, ten seconds apart. Nothing was reset and nothing was
> faked — the file was altered behind the application's back, and the system caught it on
> the next check. That failure is now in the audit trail as an INTEGRITY_FAILURE event."

Two things to say before anyone asks:

- The button exists **only under the `dev` profile**. In any other build the bean is never
  created and the route returns 404 — there is no flag to forget to switch off. Demo tooling
  that can damage evidence should not be able to reach a real deployment.
- The corruption is deliberately audited as `TAMPER_SIMULATION_EXECUTED`. Real tampering
  would leave no such entry — the audit trail then reads, in order: document committed,
  integrity passed, tampering simulated, **integrity failed**.

### Step 5 — Register evidence

Register the seized handset. Note the generated evidence code and the initial hash.

### Step 6 — Chain of custody (the strongest moment)

Transfer custody to `forensic1`. Then look at the chain.

Each event stores `SHA256(previous_hash + canonical_payload)`. The **LINK OK** badges are
computed *in the browser* by re-linking each event to its predecessor — so the judge is
watching the chain be verified, not being told it was.

> "These rows are append-only, enforced by a database trigger — not by application code.
> Even a compromised service account cannot rewrite custody history. Tampering with any
> event breaks every link after it, and that shows up here immediately."

### Step 7 — Permission-filtered search

Run the search. The box is pre-filled with **`affidavit`** deliberately: OCR is mocked, so the
indexed text is placeholder legal wording containing *affidavit*, *jurisdiction* and *subpoena*
rather than your document's real contents. Searching for words from the actual file returns
nothing, which looks like a failure if you have not said why.

> "The ABAC filter is part of the OpenSearch query itself — a mandatory `bool filter` on the
> caller's assigned cases and classification. Results are filtered *before* retrieval, so a
> document you are not entitled to never enters the result set to begin with."

Indexing is asynchronous (RabbitMQ → worker → OCR → OpenSearch), so allow a few seconds after
upload before searching.

**Ask AI (case-scoped)** runs the same retrieval through the RAG path: real permission-filtered
retrieval with real citations, and a mocked answer-generation step. Say so plainly — the
interesting engineering is the filtering, not the sentence it returns.

### Step 8 — Audit and anchoring

First, while still signed in as `inspector1`, click **Load audit trail**. It returns **403**.

> "That is the design, not a bug — audit access needs the AUDITOR or ADMIN role."

Now sign in as `auditor1` and load it again. Show the hash-chained events. Then
**Trigger anchor** followed by **Verify all batches**: audit events are batched into a
Merkle tree and the root is anchored, so any retrospective edit is detectable.

---

## 4. Questions judges tend to ask

**"Is the security real or just UI?"**
Open Swagger UI in another tab and call any `/api/v1/**` endpoint without a token — every
one returns 401. The console holds no privileges the API does not enforce itself.

**"What if someone edits the database directly?"**
`document_version`, `custody_event`, `audit_event` and `share_access` have append-only
database triggers. Beyond that, the Merkle anchoring means altering history changes the
batch root, and verification fails.

**"How does row-level security work?"**
Show it rather than describing it — that is step 3. `case_person` (the table holding PII)
carries a policy restricting rows to officers with a live, unrevoked assignment. The
application binds `app.current_user_id` per transaction; the table is `FORCE ROW LEVEL
SECURITY`; and the runtime connects as `nyayavault_app`, which holds neither SUPERUSER nor
BYPASSRLS. All three are needed — a superuser bypasses policies entirely, which is why
connecting as the database owner silently disables the whole feature.

**"What is mocked?"** — Be upfront; it reads as engineering judgement rather than a gap:

| Component | Status |
|---|---|
| Malware scanning | mock — interface ready for ClamAV |
| OCR | mock — interface ready for Tesseract |
| LLM answer generation | mock — retrieval and permission filtering are real |
| TSA / ledger anchoring | mock reference — Merkle tree construction is real |
| MFA check on share links | prefix check — Keycloak TOTP is the real target |
| CCTNS / ICJS adapters | mock adapters behind a real gateway interface |

The security architecture around each of these — permission filtering, provenance,
audit — is genuine. Only the external dependency is stubbed.

---

## 5. If something breaks mid-demo

| Symptom | Fix |
|---|---|
| Console loads but sign-in fails | Keycloak is slow to start; wait ~30s and retry |
| Every sign-in shows "Failed to fetch" | Keycloak lost its database. `docker compose up -d --force-recreate keycloak`. This was caused by `KC_DB: dev-mem` and is fixed (see below) — if it returns, check `docker logs nyayavault-keycloak` for "this database is empty" |
| Duplicate users in the transfer list | An old set of internal users from a previous realm import. `docker compose down -v` then `.\start-demo.ps1` for a clean base |
| Every API call returns 401 | token expired — sign in again |
| Search returns nothing | indexing is async; wait a few seconds and re-run |
| Audit returns 403 | expected as `inspector1` — sign in as `auditor1` |
| "No target user" on transfer | click **Provision all demo users** in step 1 |
| Containers unhealthy | `docker compose down -v` then `.\start-demo.ps1` |

Keep a browser tab on Swagger UI as a fallback: if the console misbehaves, the same flow
can be driven directly from there.

### One failure worth knowing about

Keycloak originally ran with `KC_DB: dev-mem`. That keeps its database purely in memory, and
H2 discards an in-memory database as soon as the last JDBC connection closes — which happens
after roughly 15 minutes with no logins, when the pool evicts its idle connections. The
container went on reporting healthy (its `/health/ready` returns `{"status":"UP","checks":[]}`
and never touches the database) while every login failed with "Failed to fetch".

Left alone, that is a demo killer: set up, wait for the judges, and sign-in is dead by the time
you present. Two changes fix it, both already applied:

- `KC_DB: dev-file` — the database lives on disk inside the container and cannot be dropped by
  idle-connection eviction.
- The healthcheck now fetches the realm's OIDC discovery document, which forces a real database
  read, so a Keycloak that cannot serve logins is reported unhealthy instead of healthy.

Demo users also carry pinned ids in the realm file, so re-importing the realm keeps the same
JWT `sub` and does not create a duplicate set of internal users.
