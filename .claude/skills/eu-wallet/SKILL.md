---
name: eu-wallet
description: EU Digital Identity Wallet (EUDI Wallet) domain knowledge for the EU Wallet gateway type: ARF roles and trust model, OpenID4VP verification, OpenID4VCI issuance, SD-JWT VC / mdoc, PID rulebook, access and registration certificates, status lists, wallet-based signing (QES) and PSD2 SCA (TS12). Use when planning, building, reviewing or documenting anything in docs/plans/eu-wallet-gateway.md, wallet gateway code, its console pages or docs, or when the user asks how the EUDI Wallet works.
---

# EU Digital Identity Wallet

**The source of truth is the Architecture and Reference Framework (ARF): https://eudi.dev/latest/main/.** This skill holds a digest of it, taken on 2026-11-18. Before you implement or document a rule, fetch the page it comes from and check it; the ARF changes several times a year. [reference.md](reference.md) has the exact identifiers, claim names and spec pointers.

## Where to look
| Need | Source |
|---|---|
| Roles, architecture, protocols, trust model | ARF main document: `https://eudi.dev/latest/main/0N-…/` (chapter 3 roles, 5 data model and protocols, 6 trust model) |
| High-level requirements (HLRs), by topic | `https://eudi.dev/latest/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/` |
| Technical specifications TS1–TS14 | eudi.dev pages are stubs. Fetch the raw markdown: `https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/main/docs/technical-specifications/<slug>.md` |
| PID / mDL rulebooks | `https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/main/rulebooks/pid/pid-rulebook.md` |
| Signing with the wallet | Discussion topic AB: `https://eudi.dev/latest/discussion-topics/ab-digital-signature-using-wallet/` |
| Reference implementation and conformance | `https://docs.eudi.dev/latest/`, `https://conformance.eudi.dev/latest/` |
| Protocol detail | OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP (openid.net). SD-JWT (RFC 9901) and SD-JWT VC, plus Token Status List (IETF OAuth WG). ETSI TS 119 472-2/-3 (presentation and issuance profiles), TS 119 475 (registration certificates), TS 119 411-8 (access certificates), TS 119 602 (LoTE) |

The ARF main text does not specify DCQL syntax, response modes, client_id prefixes, proof types or media types. It defers them to HAIP, OpenID4VP/VCI and ETSI TS 119 472. Read those for the exact wire format and never guess it.

## Mental model (what we are in the ecosystem)
- Phylax's wallet gateway is a **Relying Party Instance** when it verifies (OpenID4VP). When it verifies for a customer, it is an **intermediary**, which the ARF counts as a relying party itself.
  - The **access certificate** in the request identifies the intermediary.
  - The customer's **registration certificate** lists the intermediary in `usesIntermediaries`.
  - The wallet shows the user the customer's trade name.
  - The intermediary must delete the presented data immediately after forwarding it.
- When it issues (OpenID4VCI), it acts for an **attestation provider**: an EAA provider, or a PuB-EAA/QEAA provider if the customer has that status. Never a PID provider.
  - The issuer's access certificate and registration certificate go in the **signed Credential Issuer metadata**.
  - The issuer validates the **Wallet Unit Attestation**, i.e. the WIA and KA defined in TS3.
- For **qualified** signatures, only a QTSP (a QESRC provider) or the user's QSCD can create them. The gateway may be a Signature Creation Application or request a signature through OpenID4VP `transaction_data`. It must never claim a qualified signature by itself. PAdES is mandatory for wallet QES; JAdES, XAdES, CAdES and ASiC are optional.
- **"PSD" ambiguity.** TS12 covers PSD2 strong customer authentication (SCA) with the wallet, using SD-JWT VC + OpenID4VP + `transaction_data` types `urn:eudi:sca:*`. The user's term "psd" was confirmed to mean the EUDI Wallet. If payments come up, TS12 is the spec.

## Rules when building the gateway
1. **Verify fully, fail closed.** Check, in order:
   1. the issuer signature against a trust anchor, kept separate per entitlement type (LoTE / Trusted List for PID, QEAA and PuB-EAA; the rulebook for other EAAs);
   2. `nbf`/`exp` (technical validity);
   3. the status list bit, when the credential has `status`;
   4. the KB-JWT (`aud`, `nonce`, `iat` window, `sd_hash`, `transaction_data_hashes`);
   5. that each disclosure digest is present in `_sd`;
   6. that only the claims the DCQL query requested were disclosed.

   A missing trust anchor or an unknown status list fails. Never accept a credential without verifying it.
2. **Request only what the registration certificate allows.** The wallet compares the requested claims with the registered intended use and warns the user about extra ones. The console must stop a customer from configuring claims outside their intended use once we store it.
3. **Signed requests.** Authorization requests are signed JARs (`request_uri`) carrying the access certificate chain (x5c, without the root). The client_id prefix matches the certificate (`x509_san_dns:` / `x509_hash:`, per OpenID4VP 1.0). Responses use `direct_post.jwt`, encrypted with an ephemeral ECDH-ES key per session.
4. **Privacy.** The ARF treats unlinkability as a goal: PIDs are issued in batches and are short-lived. Never log claim values, disclosures or portraits; logs carry type, outcome and failure code only. Claim results are kept only for the configured retention (24 h default in the plan) and deleted after delivery when acting as intermediary.
5. **PID keys never sign transaction data.** The PID rulebook forbids it. Payment, QES and other transaction confirmation uses a dedicated attestation (TS12 SCA attestation, QES authorisation attestation).
6. **Revocation.**
   - Revocation information is required only when the validity exceeds 24 h.
   - Two mechanisms: Token Status List (URI + index, a bit check) or a revocation list (URI + identifier).
   - When we issue, we publish our own status list and the console owns revocation.
7. **Identifiers are exact strings.** Copy PID `vct`, mdoc docType and namespace, claim names and transaction data type URIs from [reference.md](reference.md) or the source. Never paraphrase them. Note that SD-JWT and mdoc claim names differ (`birthdate` vs `birth_date`, `nationalities` vs `nationality`, `picture` vs `portrait`).
8. **Scope honesty.** The plan states what isn't supported (mdoc → 501, authorization-code issuance → 501, QES needs a QTSP). Console text and docs must say the same; never present Phylax as a QTSP, PID provider or Access CA.

## Repo conventions still apply
Follow CLAUDE.md:
- models via `models/index.js`; new columns in `scripts/migrate-data.js`;
- a config shape change goes in both `services/gatewayConfig.js` and `gateway/src/runtime.js`;
- `redactConfig` hides keys, webhook secrets and sealed values;
- generic errors via `utils/http.js`; tenant scoping by `organizationId`;
- no inline scripts; console production deps plain JavaScript.

Keep the plan in `docs/plans/eu-wallet-gateway.md` and user docs (`docs/guides/eu-wallet-gateway.md`, listed in `services/docs.js`) in step with what is built.

## Answering questions
When the user asks how something works in the EUDI Wallet:
1. Answer from this skill and reference.md.
2. Fetch the ARF page for anything not covered, or anything that may have changed.
3. Cite the section, e.g. "ARF 6.6.3.7".

Say plainly when the ARF leaves something to a rulebook, an ETSI spec or the Member State.
