# CrimeNet: Zero-Trust Document & Evidence Provenance Fabric
### A Case-Centric Security Layer for the Criminal Justice Lifecycle

CrimeNet is a case-centric, zero-trust backend platform that governs the security, integrity, and lifecycle of sensitive investigation and legal records. It is designed not to replace existing systems (like CCTNS, ICJS, eSakshya, eOffice, e-Courts, or e-Forensics) but to sit alongside them as an unassailable layer of truth, controlled access, and cryptographic provenance.

**Architecture:** Spring Boot modular monolith over PostgreSQL + MinIO + OpenSearch + Redis + RabbitMQ, with Keycloak for identity and Web3j for EVM-compatible blockchain Merkle anchoring.

> ⚠️ **Legal**: See [LEGAL_DISCLAIMERS.md](LEGAL_DISCLAIMERS.md) for all compliance, admissibility, and data-privacy caveats. Watermarking, cryptographic signatures, and audit trails provide Section 65B Bharatiya Sakshya Adhiniyam (BSA) 2023 compliance.

---

## Capabilities & Architecture

This repository contains the production-ready backend and government portal console implementation for **CrimeNet**, encompassing zero-trust evidence management, cryptographic digital signatures, blockchain provenance anchoring, and police asset lifecycle management.

---

### Phase 1: Foundation & Zero-Trust Core ✅
- **Domain Modeling**: JPA entities for `CaseRecord`, `CasePerson`, `CaseAssignment`, `Document`, `DocumentVersion`, `Evidence`, `EvidenceArtifact`, `CustodyEvent`, `AuditEvent`, `SecurityEvent`, `LegalHold`, `RetentionPolicy`, `SharePackage`, `ShareAccess`, `Organization`, `Department`, `AppUser`, `Role`, `Permission`, `UserRole`, `Policy`, `DigitalSignature`, `BreakGlassGrant`, `WorkflowTransition`.
- **Row-Level Security (RLS) & AES-256-GCM**: PostgreSQL RLS activated on `case_person` table to isolate victim/witness/accused PII. Sensitive PII columns (`id_number_encrypted`, `contact_encrypted`, `address_encrypted`) are additionally encrypted at rest using authenticated AES-256-GCM via `EncryptedStringConverter`. `RlsAspect` binds `app.current_user_id` to every transaction context (§4.1).
- **ABAC+RBAC Authorization**: `PolicyEvaluationService` evaluates fine-grained access per-request against live DB state (case assignment, classification, role) — never solely from stale JWT claims (§10). Keycloak issues coarse RBAC roles; all fine-grained ABAC is server-side.
- **Versioned Policy Rules**: `Policy` entity stores declarative ABAC rule definitions (admin-only, version-tracked).
- **Integrity Layer**: `AuditService` and `HashService` for cryptographic hash-chained audit with fail-closed advisory serialization locking. Database-level `reject_update_delete` triggers on `document_version`, `custody_event`, and `audit_event` enforce append-only immutability at the DB layer (§4.2).
- **Infrastructure**: PostgreSQL, MinIO (5 buckets), OpenSearch, RabbitMQ, Redis. Docker Compose for local orchestration.

### Phase 2: Document Lifecycle ✅
- **Quarantine Pipeline**: Uploads land in `crimenet-quarantine` bucket first — never directly into documents (§5).
- **Validation & Scanning**: MIME type allowlist and 50MB size limit enforced. Mock `MalwareScannerService` inspects files in quarantine.
- **Outbox Pattern**: DB row created as `PENDING` → MinIO upload → mark `COMMITTED` + audit event atomically, preventing orphaned records (§4.3).
- **Idempotency**: Supports `Idempotency-Key` headers — duplicate uploads with same key return existing version (§6).
- **Reconciliation Worker**: Scans for stale `PENDING` rows past TTL, verifies MinIO existence, marks `COMMITTED` or `FAILED` — never silently promotes (§20).
- **Content-Hash Deduplication**: Decoupled SHA-256 content indexing prevents cross-case or cross-tenant document hijacking.
- **Server-Side Encryption**: Opt-in SSE (`minio.sse-enabled: true` for AWS S3/KMS or MinIO KES). Local standalone MinIO defaults to false because plain local containers lack a KES key broker (§5).
- **Quarantine Auto-Expiry**: 24-hour lifecycle rule on the quarantine bucket auto-purges abandoned uploads (§5).
- **Event Publishing**: `RabbitMqPublisher` emits `DOCUMENT_VERSION_CREATED` events for async downstream processing.

### Phase 3: Evidence & Chain of Custody ✅
- **Evidence Registration**: Records physical/digital evidence with a cryptographic initial hash and collection metadata.
- **Evidence Artifacts**: `EvidenceArtifact` entity tracks physical/digital artifacts under an Evidence record — immutable once registered (§3).
- **Hash-Linked Custody Chain**: Each `CustodyEvent.event_hash = SHA256(previous_event_hash + canonical_payload)`, enforced append-only by DB trigger (§7).
- **Pessimistic & Optimistic Locking**: Concurrent custody transfers are locked using a database row-level lock (`SELECT ... FOR UPDATE`) with mandatory `previous_event_id` verification to eliminate TOCTOU race conditions and prevent split-brain custody forks (§7).
- **Evidence Artifacts Pipeline**: Digital artifacts go through quarantine → scan → server-side copy flow into the `crimenet-evidence` bucket.

### Phase 4: RabbitMQ & Async Processing ✅
- **RabbitMQ Listener**: `DocumentMessageListener` consumes events asynchronously.
- **Mock OCR**: `OcrService` simulates text extraction (placeholder for Tesseract/Cloud Vision).
- **Dead-Letter Queues (DLQ)**: Full DLX/DLQ topologies with exponential backoff for Document, OCR, and Integrity exchanges (§13).
- **End-to-End Tracing**: `CorrelationIdFilter` assigns `TRC-*` correlation IDs to every request, propagated into SLF4J MDC → RabbitMQ message headers → async workers → Audit Event payloads for full distributed tracing (§13, §20).
- **Worker Idempotency**: Workers are idempotent by job ID — reprocessing the same message is a no-op if a result already exists (§13).
- **Pipeline**: Listener downloads document → extracts text → pushes to OpenSearch index.

### Phase 5: OpenSearch & Search ✅
- **Full-Text Indexing**: Documents indexed with `documentId`, `caseId`, `hash`, `classification`, `authorizedRoles`, `authorizedUserIds`, and extracted text (§14).
- **Zero-Trust Retrieval**: Every query includes a **mandatory `bool filter`** on ACL fields built server-side from the requester's context — restricted documents are excluded *before* ranking, never filtered from results afterward (§14).

### Phase 6: Secure Sharing & Break-Glass Access ✅
- **SharePackage CRUD**: Manage share packages with recipient, purpose, scope, rights, expiry. **No public links ever — every share requires an authenticated recipient identity** with strict BOLA checks on `getShare` (§11).
- **Pre-Signed Download URLs**: Secure 300-second (5-minute) pre-signed SigV4 URLs passed unaltered to prevent signature mismatch, returning separate watermark metadata in the response JSON (§5).
- **Watermark Directives**: Watermark directives returned alongside download URLs for frontend viewer rendering (§2 #10: deterrent/traceability controls, not prevention).
- **Access Logging**: Dedicated `ShareAccess` ledger records every access action (§11).
- **MFA Step-Up Enforcement**: Mandatory structured step-up MFA validation required before accessing restricted shares or emergency access (§11).
- **Break-Glass Emergency Flow**: `BreakGlassService` provides time-boxed (30 min), reason-based, view-only emergency access with a sliding rate limit (max 3 per 24 hours per officer) and mandatory structured MFA step-up. Integrated into `PolicyEvaluationService`. Auto-revoked via scheduled jobs. Mandatory supervisor alert logged via `SUPERVISOR_NOTIFIED_BREAK_GLASS` audit event (§11).

### Phase 7: Cryptographic Provenance ✅
- **Merkle Tree Batching**: `AnchorService` batches unanchored audit events every 5 minutes into a Merkle Tree (§8).
- **External Anchoring**: Only the Merkle Root + batch metadata is anchored to a mock TSA — **never file contents, PII, victim/witness identity, or case content** (§8).
- **Verification API**: Rebuild the Merkle tree and compare against the external anchor. A mismatch flags `INTEGRITY_FAILURE` — proves non-tampering beyond internal self-consistency (§9).
- **Why this matters**: Internal hash-chaining alone only proves self-consistency. A DBA could rewrite the chain. The external anchor closes this gap — the anchor step is non-negotiable, not decorative (§9).

### Phase 8: AI/RAG ✅
- **AI Orchestration**: `AIService` implements RAG with strict permission-aware pre-retrieval filtering (§14).
- **Provenance Tracking**: `AIJob`, `AIResult`, and `AIReference` entities record user, query, model version, retrieved document IDs + chunk references, and generated response (§15).
- **Read-Only**: AI has **no write path** to `document`, `document_version`, `evidence`, or `custody_event` tables — read/summarize/classify/suggest only (§15).

### Phase 9: Integration Gateway ✅
- **Adapter Pattern**: `ExternalSystemAdapter` interface with `MockCctnsAdapter` and `MockIcjsAdapter` returning realistic sample data. Switching to real adapters is a config/credential change only (§16).
- **Gateway Service**: Routes fetch/push/health/sync calls to the correct adapter by system name.
- **Local Tracking**: `ExternalReference` and `SyncJob` entities track synchronization state (§16).

### Additional: Retention & Legal Holds ✅
- **Lifecycle Flow**: `ACTIVE → SEALED → ARCHIVED → RETENTION_REVIEW → DISPOSITION`. Legal holds block the DISPOSITION transition entirely at both the service layer and Object Lock layer (§12).
- **Workflow Engine**: `WorkflowService` and `WorkflowTransition` entity govern lifecycle state transitions with approval tracking.
- **Legal Hold Management**: Apply/release holds on cases with full audit trail. Deletion/disposition is never a direct DELETE — it's an approval-based workflow (§12).

### Additional: Digital Signatures ✅
- **Signature Entity**: `DigitalSignature` entity tracks cryptographic signing metadata for document versions (§3). Immutable once created.

---

## Project Structure (§18)

```
backend/src/main/java/com/nyayavault/
├── identity/          (users, keycloak sync)
├── organization/
├── policy/            (RBAC+ABAC engine, versioned Policy entity)
├── cases/             (CaseRecord, CasePerson, CaseAssignment)
├── documents/         (Document, DocumentVersion, HashService, OcrService)
├── evidence/          (Evidence, EvidenceArtifact, CustodyEvent)
├── provenance/        (MerkleBatch, MerkleTreeService, AnchorService)
├── workflow/          (WorkflowTransition, WorkflowService)
├── sharing/           (SharePackage, ShareAccess)
├── retention/         (LegalHold, RetentionPolicy, RetentionService)
├── search/            (OpenSearch client, ABAC-filtered search)
├── audit/             (AuditEvent, hash-chained, append-only)
├── security/          (BreakGlassService, RlsAspect, CorrelationIdFilter, SecurityEvent)
├── signatures/        (DigitalSignature)
├── ai/                (AIService, AIJob, AIResult, AIReference)
├── integrations/      (IntegrationGateway, adapters, ExternalReference, SyncJob)
├── common/            (ApiResponse, BaseEntity, exceptions)
├── infrastructure/    (MinIO, RabbitMQ, Redis config, IdempotencyRecord)
└── worker/            (DocumentMessageListener, ReconciliationWorker)
```

---

## API Endpoints (§17)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/cases` | INVESTIGATOR+ | Create case |
| GET | `/api/v1/cases/{id}` | case-assigned | Get case (ABAC checked) |
| POST | `/api/v1/cases/{caseId}/documents` | case-assigned | Upload document (quarantine pipeline, idempotency) |
| GET | `/api/v1/documents/{id}/versions` | case-assigned | List immutable versions |
| GET | `/api/v1/documents/{id}/integrity` | case-assigned/AUDITOR | Verify document hash integrity |
| POST | `/api/v1/evidence` | FORENSIC_OFFICER/INVESTIGATOR | Register evidence |
| POST | `/api/v1/evidence/{id}/custody` | assigned + signature | Transfer custody (optimistic lock) |
| POST | `/api/v1/evidence/{id}/artifacts` | case-assigned | Upload evidence artifact |
| GET | `/api/v1/search?q={query}` | case-assigned | ABAC-filtered full-text search |
| POST | `/api/v1/shares` | case-assigned | Create share package |
| GET | `/api/v1/shares/{id}/download/{versionId}` | recipient/creator | Secure download (pre-signed URL, MFA) |
| POST | `/api/v1/break-glass` | any authenticated | Request emergency break-glass access |
| POST | `/api/v1/cases/{caseId}/legal-holds` | SUPERVISOR+ | Apply legal hold |
| POST | `/api/v1/documents/{id}/archive` | case-assigned | Archive document (legal-hold aware) |
| GET | `/api/v1/integrations/{system}/fetch/{id}` | case-assigned | Fetch from external system |
| POST | `/api/v1/integrations/{system}/push/{type}/{id}` | case-assigned | Push to external system |
| POST | `/api/v1/integrations/{system}/sync` | ADMIN | Trigger adapter sync job |
| POST | `/api/v1/provenance/anchor` | ADMIN | Manually trigger Merkle anchoring |
| GET | `/api/v1/provenance/verify` | AUDITOR | Verify Merkle chain integrity |
| POST | `/api/v1/ai/query` | case-assigned | Permission-aware RAG query |
| GET | `/api/v1/audit` | AUDITOR | Read-only, paginated, filterable |

All mutating endpoints support: `Idempotency-Key` header, explicit audit event, explicit transaction boundary, and error taxonomy (`400`/`401`/`403`/`404`/`409`/`422`/`500`).

---

## MinIO Buckets (§5)

| Bucket | Purpose | Security |
|---|---|---|
| `nyayavault-quarantine` | Unscanned uploads, 24h auto-expiry | SSE, lifecycle rule |
| `nyayavault-documents` | Sealed document versions | SSE, org/case partitioned |
| `nyayavault-evidence` | Evidence artifacts | SSE, WORM-eligible |
| `nyayavault-court-packages` | Generated export bundles | SSE, time-limited |
| `nyayavault-archive` | Cold tier, legal-hold protected | SSE, WORM/Object Lock eligible |

> **Note**: Object Lock (WORM) for `nyayavault-evidence` and `nyayavault-archive` is architecturally designed but requires MinIO server configuration. The application enforces immutability at the service and DB trigger layers; Object Lock provides defense-in-depth at the storage layer.

---

## Security Threat Model (§19)

| Threat | Control | Detection |
|---|---|---|
| Stolen credentials | MFA, short sessions, device trust | Anomalous login alerts |
| Insider misuse | ABAC + case assignment + purpose logging | `POLICY_DENIED` audit, anomaly rules |
| Document tampering | Immutable versions, SHA-256, DB triggers | Integrity verification job |
| Audit tampering | Append-only + hash chain + external Merkle anchor | Anchor mismatch alert |
| Unauthorized export | Policy engine, watermark, expiry | Bulk-download alert |
| Malicious upload | Quarantine, MIME check, malware scan | Scan-fail audit |
| AI leakage | Pre-retrieval ACL filter (never post-filter) | RAG-source audit trail |
| Ransomware | Immutable/WORM backups, isolated creds | Backup integrity checks |

Additional: TLS everywhere, secrets in vault (not env files in prod), least-privilege DB roles, parameterized queries (JPA), CORS locked to known origins, rate limiting on auth/export endpoints, UUID-based object keys (never user-supplied filenames).

---

## Tech Stack

| Component | Technology |
|---|---|
| Runtime | Java 21, Spring Boot 3.4.x |
| Database | PostgreSQL 16 |
| Object Storage | MinIO (5 buckets) |
| Message Queue | RabbitMQ |
| Search Engine | OpenSearch |
| Cache | Redis |
| Identity | Keycloak (JWT + RBAC) |
| Containerization | Docker Compose |

## Testing Strategy (§21)

Unit (hashing, versioning, policy evaluation, custody transitions) → Integration (Postgres/MinIO/RabbitMQ/OpenSearch via Testcontainers) → Security (broken object-level auth, token replay, upload attacks, export abuse) → Integrity (tamper a version/audit/custody row and confirm detection) → End-to-end demo (Case CASE-2026-UP-004281 storyline).

## Getting Started

```bash
# Start infrastructure
docker-compose up -d

# Compile and verify
./mvnw clean compile
```
