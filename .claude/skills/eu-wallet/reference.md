# EUDI Wallet: reference digest (taken 2026-11-18 from eudi.dev and the EUDI GitHub repositories)

Check against the source before relying on a value. Section numbers are ARF main-document sections.

## Roles (ARF 3)
- **User**, **Wallet Provider**, **PID Provider**
- **QEAA Provider:** a QTSP.
- **PuB-EAA Provider:** a public body, or one acting for it, tied to an authentic source.
- **EAA Provider:** non-qualified.
- **QESRC Provider:** a QTSP for remote qualified signatures and seals.
- **Authentic Source**
- **Relying Party**, split into RP Service and RP Instance.
- **Intermediary:** deemed to be a relying party.
- **Registrar**
- **Access CA:** issues access certificates.
- **Provider of registration certificates:** issues JWTs giving registration status and scope.
- **LoTE / Trusted List Provider**
- **Attestation Scheme Provider**, **CAB**, **NAB**, **Supervisory Body**

## Formats (ARF 5)
| Format | Wallet support | Notes |
|---|---|---|
| ISO/IEC 18013-5 / 23220-2 mdoc (CBOR) | mandatory | Proximity and remote (18013-7, Annex A custom scheme / Annex C DC API). Device binding mandatory |
| SD-JWT VC (`dc+sd-jwt`) | mandatory | Remote only. Device binding optional, recommended |
| W3C VCDM 2.0 | optional | Non-qualified EAAs only |

- Remote presentation: OpenID4VP + HAIP, through a custom URI scheme redirect or the W3C Digital Credentials API.
- Issuance: OpenID4VCI + HAIP.
- Batch issuance gives a different technical PID per presentation, which prevents linking.

## Trust checks
**Wallet authenticates the RP (6.6.3.2)**
- The request carries the access certificate and intermediates (no root) and is signed.
- The wallet validates the chain to the Access CA anchor from the LoTE and checks CRL/OCSP (RFC 5280, ETSI TS 119 411-8).

**Registration certificate (6.6.3.3)**
- The wallet checks signature, expiry and revocation, that the RP and Service identifiers match the access certificate (or the intermediary rules apply), and that the requested attributes are within the registered ones.

**RP verifies the attestation**
- **Issuer signature (6.6.3.6):** verified against the LoTE / Trusted List anchor. Anchors are kept per entitlement type.
- **Revocation (6.6.3.7):** required only if validity > 24 h. Token Status List (URI + index) or revocation list (URI + id). Checking is recommended; without status, the RP does a risk analysis.
- **Device binding (6.6.3.8):** proof of possession over a fresh nonce. OpenID4VP `require_cryptographic_holder_binding`.
- **User binding (6.6.3.9):** wallet authentication (default), portrait match, or a physical document.
- **Combined presentation (6.6.3.10):** the RP must establish that attestations belong to the same user.

**Issuance (6.6.2)**
- The wallet verifies the issuer's access certificate and signed metadata, then the registration certificate (entitlement covers the attestation type).
- The issuer verifies the WIA and KA (TS3) against Wallet Provider anchors. Attestation providers must accept all Wallet Providers.
- Key binding to the session uses a nonce: either the KA contains the nonce, or a key listed in the KA signs it.
- The PID's technical validity is no longer than the KA/WIA revocation period.

**Embedded disclosure policies (6.6.2.8, ETSI TS 119 472-3)**
- Values: "No policy", "Authorised relying parties only", "Specific root of trust".
- They are published in the issuer metadata. Changing a policy means revoking the attestation.

**Intermediary (6.6.5)**
- The access certificate is the intermediary's. The intermediated RP's registration certificate has `usesIntermediaries`.
- The user sees the end RP's names. The intermediary deletes data after forwarding it; deletion requests go to the RP.

## PID rulebook
- SD-JWT VC `vct`: `urn:eudi:pid:1`. National types use `urn:eudi:pid:<cc>:1`.
- mdoc docType and namespace: `eu.europa.ec.eudi.pid.1`.

| Attribute | mdoc | SD-JWT VC |
|---|---|---|
| family name * | `family_name` | `family_name` |
| given name * | `given_name` | `given_name` |
| birth date * | `birth_date` | `birthdate` |
| birth place * | `place_of_birth` | `place_of_birth` {country, region, locality} |
| nationality * | `nationality` | `nationalities` (array, alpha-2) |
| portrait * | `portrait` (bstr) | `picture` (data URL) |
| address | `resident_address`, `resident_country`, `resident_state`, `resident_city`, `resident_postal_code`, `resident_street` | `address.formatted`, `.country`, `.region`, `.locality`, `.postal_code`, `.street_address`, `.house_number` |
| personal administrative number | `personal_administrative_number` | same |
| birth names | `family_name_birth`, `given_name_birth` | `birth_family_name`, `birth_given_name` |
| sex | `sex` | `sex` |
| email / phone | `email_address`, `mobile_phone_number` | `email`, `phone_number` |
| issuing authority * / country * | `issuing_authority`, `issuing_country` | same |
| expiry / issuance (administrative) | `expiry_date`, `issuance_date` | `date_of_expiry`, `date_of_issuance` |
| other metadata | `document_number`, `issuing_jurisdiction`, `trust_anchor`, `attestation_legal_category` | same |

- \* marks mandatory attributes.
- Technical validity is `nbf`/`exp`.
- A PID key must not sign RP transaction data.

## TS5: relying party registration (Registrar API, read-only, JWS-signed responses)
**Data model**
- `WalletRelyingParty`: `identifier`, `tradeName`, `isPSB`, `supervisoryAuthority`, `registryURI`, `services[]`.
- Each service: `serviceTradeName`, `serviceIdentifier`, `intendedUses[]`, `entitlements`, `providesAttestations`, `usesIntermediaries[]`, `isIntermediary`, `servedWRPServices[]`, `status` (`active` | `suspended` | `revoked`).
- `IntendedUse`: `purpose`, `privacyPolicy`, `intendedUseIdentifier`, `credentials[]`. Each credential has `format`, `meta.vct_values` / `meta.doctype_value`, and `claims[].path`.
- `ServiceReference`: `identifier`, `serviceIdentifier`, `registryURI`.

**Endpoints**
- `GET /wrp`, with filters such as `identifier`, `serviceIdentifier`, `entitlement`, `usesIntermediary`, `isIntermediary`, `credentialFormat` (percent-encode `dc%2Bsd-jwt`).
- `GET /wrp/{identifier}`
- `GET /wrp/check-intended-use`
- `GET /wrp/{identifier}/services/{serviceIdentifier}`

**Rules**
- A pure intermediary registers no entitlement.
- The registration certificate format itself is ETSI TS 119 475; one certificate per intended use.

## TS12: PSD2 SCA with the wallet (v1.0.1)
**Attestation**
- An SCA attestation is identified by the type-metadata `category` = `urn:eu:europa:ec:eudi:sua:sca`. `vct` values come from the rulebook. Holder key in `cnf.jwk`.
- The metadata maps `transaction_data_types`, each to `schema`/`schema_uri`, `claims`/`claims_uri` and `ui_labels`/`ui_labels_uri`.

**`transaction_data` entry:** `type`, `credential_ids`, `transaction_data_hashes_alg`, `payload`.

**Types**
- `urn:eudi:sca:payment:1`
  - Required: `transaction_id`, `payee{name,id}`, `currency`, `amount`.
  - Optional: `pisp{legal_name,brand_name,domain_name}`, `recurrence{frequency,…}`, `execution_date`, `amount_estimated`, `amount_earmarked`, `sct_inst`, `date_time`.
- `urn:eudi:sca:login_risk_transaction:1`: `transaction_id`, `action`; optional `service`.
- `urn:eudi:sca:account_access:1`: `transaction_id`; optional `aisp{…}`, `description`.
- `urn:eudi:sca:emandate:1`: `transaction_id`; `purpose` (required when `payment_payload` is absent), plus `start_date`, `end_date`, `reference_number`, `creditor_id`, `payment_payload`.

**KB-JWT**
- Adds `jti` (the PSD2 authentication code), `response_mode`, and `amr` (at least 2 of knowledge / possession / inherence), plus `transaction_data_hashes` and `transaction_data_hashes_alg`.
- The hash computation is defined by OpenID4VP, not TS12.

## Signing with the wallet (discussion topic AB)
**QSCD location**
- The QSCD may be local, external or remote.
- Remote: OpenID4VP per ETSI TS 119 432 and CEN EN 419 241-2 (QES_04a). CSC API recommended for certificate issuance and signing with a remote QES provider (QES_07a/b).

**Signature Creation Application (SCA)**
- In the wallet or external (wallet provider, QTSP or RP).
- The RP may supply the data to be signed and send the request through the wallet or directly to the QTSP.
- The QTSP holds liability for compliant creation.

**Formats**
- PAdES is mandatory (QES_08, EN 319 142-1).
- Optional: XAdES, JAdES (TS 119 182-1), CAdES, ASiC.

**User consent**
- The wallet displays the request and obtains user consent (QES_10a/14a). Users may disable signing (QES_23).

## Technical specifications index
| TS | Subject |
|---|---|
| TS1 | Trust mark |
| TS2 | Provider notification and publication |
| TS3 | Wallet Unit Attestation (WIA/KA) |
| TS4 | ZKP |
| TS5 | RP registration formats and API |
| TS6 | RP registration data |
| TS7 | Data-deletion requests |
| TS8 | Reporting RPs to DPAs |
| TS9 | Wallet-to-wallet interactions |
| TS10 | Data export and portability |
| TS11 | Catalogues of attributes and schemes |
| TS12 | PSD2 SCA |
| TS13 | zkSNARK |
| TS14 | ZKPs from MMS |
