# CrimeNet — Legal Disclaimers

> **This document is referenced by all API documentation and UI components.
> All compliance-related language must originate here — never decided ad hoc per screen or endpoint.**

---

## 1. Compliance Status

CrimeNet is a **prototype / proof-of-concept** system. It does **not** currently hold any formal compliance certifications. Specifically:

- **NOT certified** under the Digital Personal Data Protection Act, 2023 (DPDP).
- **NOT certified** under ISO 27001, SOC 2, or any comparable information security standard.
- **NOT approved** as a legally admissible evidence management system under the Indian Evidence Act, 1872 or the Bharatiya Sakshya Adhiniyam, 2023.
- **NOT audited** by any independent third-party security assessor.

Any production deployment would require formal legal review, security audit, and compliance certification before handling real case data.

---

## 2. Evidence Admissibility

CrimeNet provides **technical controls** to support evidence integrity (SHA-256 hashing, append-only audit chains, Merkle anchoring, chain-of-custody tracking). However:

- Technical tamper-evidence **is not the same as legal admissibility**. Courts determine admissibility based on jurisdiction-specific rules, expert testimony, and procedural compliance — not software features alone.
- The system **does not generate** legally binding digital signatures under the Information Technology Act, 2000 (Section 3A / Schedule II).
- Hash verification and Merkle anchoring prove *technical integrity*, not *legal provenance*.

---

## 3. Watermarking & View-Only Controls

Watermarking and view-only rendering are **deterrent and traceability controls**, not prevention controls. A view-only, watermarked PDF viewer can still be screenshotted or photographed. The system documents this in its threat model rather than overclaiming enforcement.

---

## 4. Data Privacy

- PII (victim/witness/accused identity) is encrypted at rest using AES-256-GCM authenticated encryption (`EncryptedStringConverter`) and isolated behind PostgreSQL Row-Level Security (RLS). Prototype environments use local application keys; production deployments must integrate an external HSM/KMS.
- Prototype environments may use self-signed certificates, local storage, and non-hardened configurations that would be unacceptable in production.
- Data retention and deletion capabilities exist but have **not been validated** against DPDP data principal rights requirements.

---

## 5. External System Integration

Mock adapters for CCTNS, ICJS, and other government systems return **simulated data only**. No actual connection to government infrastructure exists. Integration claims refer exclusively to the architectural pattern (adapter interface), not to operational connectivity.

---

*This document must be reviewed by legal counsel before any production deployment.*
