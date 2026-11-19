# Plan: the EU Digital Identity Wallet gateway

Status: **phases 1 and 3 implemented (2026-11-19) with software keys**; phases 2 and 4 open. User guide: `docs/guides/eu-wallet-gateway.md`.

**Built:**
- Gateway kinds `api` / `wallet-verifier` / `wallet-issuer`, configuration schema 3 (API gateways unchanged at schema 2).
- The Wallet page and its REST API, and one-step Setup (built-in API, product, provider-server application).
- The OpenID4VP verifier: JAR with x5c, `x509_san_dns` / `x509_hash`, DCQL, `direct_post.jwt` (ECDH-ES) and SD-JWT VC verification with Token Status List.
- The OpenID4VCI issuer: pre-authorized code with `tx_code`, DPoP, nonce, proofs, batch, signed metadata, claims fetched from the provider server, status list per node block, revocation from the console or the provider API, optional wallet attestation.
- OAuth client-credentials connections, signed and retried callbacks, and events drained with usage.

**Differences from this plan:**
- Built-in APIs are answered by the gateway after the port flow, not as flow-editor steps.
- Trust anchors and status-list entries travel in the configuration (auto-push), not as separate trust data. Foreign status lists are fetched by the gateway (cached up to 5 min, fail closed), not pushed by the console.
- Per-operation scopes and mTLS-bound tokens for the provider server are not done.
- Trusted-list XML import is not done.
- `UsageRecord.billable` is not done.
- Only sealed keys exist. QEAA and PuB-EAA issuers are refused until phase 2 brings HSM/KMS keys.

## Scope

The product (console "MGMT" + gateway) adds a new kind of gateway, sold as a **dedicated gateway per client**. When an org admin creates a gateway they choose:

- **API gateway**: what exists today. It does not change.
- **Wallet gateway: Attestation Provider.** For a QTSP (QEAA), a public body (PuB-EAA) or a TSP (EAA). The gateway **issues** the client's attestations into EU Digital Identity Wallets (OpenID4VCI).
- **Wallet gateway: Relying Party / Verifier.** The gateway **requests and verifies** credentials presented by wallets (OpenID4VP), for example PID, mDL or diplomas.

**What the client brings is only:**
1. **Its certificates.** These are uploaded in the console and pushed to the gateway:
   - the access certificate, from an Access CA;
   - the registration certificate(s), from the registrar;
   - for an issuer, the issuer signing certificate.
   
   Private keys stay in the client's HSM or KMS, and the gateway holds only a reference. A sealed software key is allowed for tests and for non-qualified use.
2. **Its provider server.** This is the client's own backend.
   - An issuer's backend holds the attribute data and decides who gets an attestation.
   - A verifier's backend starts verifications and receives the verified claims.

**The gateway does everything protocol- and crypto-related.** The client's server never touches OpenID4VP, OpenID4VCI, SD-JWT, JAR, JWE, status lists or trust lists. It calls plain REST endpoints, and the gateway calls back with plain JSON.
- For an **issuer**, the gateway:
  - signs the credentials, the issuer metadata and the status lists;
  - validates the wallet's proofs and its wallet attestation.
- For a **verifier**, the gateway:
  - signs the request objects;
  - decrypts the responses;
  - validates the issuer signatures, trust chains, key binding and revocation.

Between the provider server and the gateway, **both directions use OAuth 2.0 client credentials**, with mTLS as an option (section 4).

## 1. Roles in the EUDI ecosystem (ARF)

| Gateway role | ARF role of the **client** | What Phylax is | Client's certificates |
|---|---|---|---|
| Attestation Provider | QEAA Provider (a QTSP), PuB-EAA Provider or EAA Provider (ARF 3) | The technical operator of the client's issuing service. The client stays the issuer of record. | Access certificate, published in the signed Credential Issuer metadata (ARF 6.6.2.2). Registration certificate listing the attestation types (6.6.2.3). Issuer signing certificate (`x5c` in each credential). |
| Relying Party / Verifier | Relying Party, operating its own **RP Instance** (ARF 3) | The operator of the client's RP Instance. **Not** an intermediary, because the access certificate is the client's own. | Access certificate, carried in each signed request (6.6.3.2). Registration certificate per intended use (6.6.3.3, TS5). |

The client is the issuer or relying party of record. Phylax never appears as issuer, relying party, QTSP or Access CA. That is why the client must bring the certificates.

Phylax acting as an **intermediary** for clients without their own access certificate stays possible later (`usesIntermediaries` in TS5). It is not in this plan.

## 2. How it maps onto what exists

| Need | Existing piece reused | New |
|---|---|---|
| Choose the gateway | Gateway create form; configuration push over mTLS; push and pull nodes | `Gateway.kind` = `api` \| `wallet-issuer` \| `wallet-verifier`, fixed after creation; configuration `schema: 3` for wallet kinds only |
| One client per gateway | A gateway belongs to one organization and serves one catalog | A **setup wizard** creates the built-in catalog, API, product and the provider server's application with a subscription. The client gets one ready-to-use gateway. |
| Provider server → gateway auth | `POST /oauth/token` (client credentials, RS256 JWT); approved subscriptions; rate limits; usage | Optional **mTLS-bound tokens** for provider servers (RFC 8705) |
| Gateway → provider server auth | Connections (timeouts, retries, circuit breaker, basic/bearer/header auth, mTLS client certificate) | New connection auth type **`oauth2-client-credentials`**: a token URL, `client_secret_basic` or `private_key_jwt`, scope and audience, with the token cached until it expires. It is also usable by API gateways. |
| Wallet calls without a token | Public operations (`x-gateway-access: public`) | — |
| Customisation | Flows around operations: Security, scripts, If, Invoke | Built-in steps for the wallet operations, with settings in the console |
| Short-lived state | Redis client (cluster rate limits) | Session store: Redis, or memory on a single node |
| No database on the gateway | Configuration cached on disk; usage drained to the console | **Trust data** (anchors, status lists) pushed outside the configuration hash. **Events** (verifications, issued credentials) drained to the console like usage. |
| Billing | Product billing plans (stored, not invoiced); usage per operation | `UsageRecord.billable`: only issuing a credential, starting a verification and each signature count |

## 3. Decisions (my recommendations)

1. **Dedicated gateway.**
   - One wallet gateway serves **one client organization and one role**.
   - A client needing both roles gets two gateways.
   - The nodes are the client's: on Phylax infrastructure or the client's own. They are never shared with another client, so the client's keys, data and logs stay isolated.
2. **Client identity everywhere.** Every signature the wallet sees uses the client's certificates: request objects, issuer metadata, credentials and status lists. The console refuses to deploy without them (section 9 problems).
3. **Keys.**
   - Providers: **AWS KMS** and **Azure Key Vault** (REST, credentials from the node's role or managed identity, no SDKs), and **PKCS#11 through a small signer sidecar**, so the gateway stays plain JavaScript.
   - **Sealed software keys** are allowed for tests and EAA pilots, and are refused for QEAA and PuB-EAA.
   - A **QTSP** client must use its own HSM (QSCD) through PKCS#11 or KMS; the console marks the issuer as qualified only then.
4. **Personal data.**
   - **Verifier:** the claims are posted to the provider server and deleted from the gateway once delivered (kept at most for the retention period, 24 h by default, while delivery retries).
   - **Issuer:** the claims are fetched from the provider server at redemption time and never stored. An option allows sending them in the offer, kept until redeemed or expired.
   - The console stores metadata only: status, type, claim **names** and times.
5. **Issuance flow.** The **pre-authorized code** flow, with an optional transaction code. The provider server authenticates the person in its own portal and asks the gateway for an offer. The **authorization code** flow returns 501 in this plan.
6. **Wallet attestation.**
   - The issuer gateway validates the wallet's **Wallet Unit Attestation** (WIA and key attestation, TS3) against Wallet Provider trust anchors. Attestation providers must accept every recognised Wallet Provider (ARF 6.6.2.4).
   - It requires a key attestation when the credential type demands a minimum key storage level.
7. **Revocation.**
   - **Issuer:** the gateway publishes the client's Token Status List. Revocation and suspension are done from the console or by the provider server (`POST /credentials/{id}/revoke`).
   - **Verifier:** the console fetches foreign status lists and pushes them. A list the console hasn't fetched yet **fails closed** with `status_unavailable`, and the console fetches it within seconds.
8. **Trust anchors.**
   - Sources: PEM upload, or EU / national trusted lists and LoTE URLs fetched by the console.
   - The XML signature is checked against pinned signer certificates. This adds `@xmldom/xmldom` and `xml-crypto`, both plain JavaScript.
   - Anchors are kept **per entitlement type**: PID, QEAA, PuB-EAA, EAA and Wallet Provider.
9. **Formats.** **SD-JWT VC** (`dc+sd-jwt`) is implemented fully for both roles. **mdoc** returns 501 in this plan and gets its own task behind the same `CredentialVerifier` / `CredentialSigner` interfaces.
10. **Signing as a service.** Validating and signing arbitrary messages for API traffic (RFC 9421, JWS, JAdES-B) was in the earlier plan. It moves to **phase 4**, on API gateways and on both wallet kinds, reusing the key providers from phase 2.

## 4. Provider server ↔ gateway (OAuth)

**Provider server → gateway.** This is the existing OAuth flow:
1. The wizard creates an application named "Provider server" in the client's organization, subscribed to the built-in product. Its client secret is shown once.
2. The provider server gets a token with `POST /oauth/token`, `grant_type=client_credentials`. Both secret forms are accepted: HTTP Basic, and the form-encoded client ID and secret.
3. It calls the gateway with `Authorization: Bearer`.
4. **Optional, per application:** require a client certificate. The console stores the certificate fingerprint. `/oauth/token` puts `cnf.x5t#S256` in the token, and the gateway checks that the TLS client certificate matches (RFC 8705). The token can't be used from anywhere else.
5. Scopes are per operation: `wallet.offers`, `wallet.credentials.revoke`, `wallet.verifications`. The product grants them and the gateway checks them.

**Gateway → provider server.** This is a connection, with the new `oauth2-client-credentials` auth type:
- The settings are the token URL, client ID, the client authentication method and scope/audience.
  - The method is `client_secret_basic`, with the secret sealed in the console.
  - Or it is `private_key_jwt`, signed with a key the console generates; the client registers its public JWK.
- The gateway gets a token, caches it until shortly before `exp`, and refreshes it on a 401 once.
- It can be combined with the connection's mTLS client certificate.
- The token and secret never appear in logs, previews or the request log. `redactConfig` hides the secret and the key.

**Callbacks** (gateway → provider server) are signed in addition to OAuth: `X-Wallet-Signature: t=…,v1=HMAC-SHA256(body)`. They are retried after 5 s, 30 s, 2 min, 10 min and 1 h, then marked failed in the console.

## 5. Phases

| Phase | Delivers | Needs |
|---|---|---|
| **1. Foundation + Verifier** | Gateway kinds and the wizard; certificates; trust data; the OAuth connection type; mTLS-bound tokens; the SD-JWT VC verifier; the OpenID4VP verifier API | Sealed or KMS key for the access certificate |
| **2. Key providers** | AWS KMS, Azure Key Vault, PKCS#11 sidecar; **Test sign** in the console | The client's HSM or KMS for production |
| **3. Attestation Provider** | OpenID4VCI issuer, wallet attestation checks, the client's status lists, revocation | Phase 2 |
| **4. Signing as a service** | RFC 9421, JWS, JAdES-B sign and verify steps and API, with a signature audit | Phase 2 |

Each phase ends with `npm test` passing and its docs written.

## 6. Phase 1: Relying Party / Verifier gateway

**Built-in API *Credential verification*** (base path `/wallet/verify`, step `walletVerification`):

| Operation | Caller | Behaviour |
|---|---|---|
| `POST /verifications` | provider server (token, scope `wallet.verifications`) | Body `{ credentialType, claims?, redirectUri?, reference? }`.<br>The claims must be within the type's claims **and** the registration certificate's intended use; otherwise 403 naming the claim.<br>Creates a session: id, nonce, state, ephemeral ECDH key.<br>Answers `201 { id, status, expires_at, request_uri, deep_link: 'openid4vp://…', qr }`. |
| `GET /verifications/{id}` | provider server | `{ status, reason?, claims? }`. Claims are present only while not yet delivered by callback. |
| `GET /oid4vp/request/{id}` | wallet, public | Signed request object (`typ: oauth-authz-req+jwt`), with:<br>• `x5c` = the client's access certificate chain without the root;<br>• `client_id` = `x509_san_dns:<host>`, or `x509_hash:` when the SAN doesn't match;<br>• `response_mode` = `direct_post.jwt`, plus `response_uri`, `nonce`, `state`;<br>• `dcql_query`;<br>• `verifier_info` with the registration certificate;<br>• `client_metadata` with the encryption JWK.<br>Served once; later calls get 410. |
| `POST /oid4vp/response/{id}` | wallet, public | JWE `response` (ECDH-ES + A128GCM/A256GCM), or `vp_token` when the client allowed `direct_post`. Verifies the credential, then POSTs `{ id, reference, status, credentialType, claims }` to the provider server's callback and deletes the claims once it gets a 2xx. Answers `{ redirect_uri? }`. |

**SD-JWT VC verification** uses `node:crypto` only and fails closed:
1. **Issuer JWT:**
   - `typ` is `dc+sd-jwt`;
   - the algorithm is ES256, ES384, PS256 or EdDSA;
   - `vct` is one of the type's values;
   - `nbf`/`exp` are valid.
2. **`x5c` chain:**
   - each certificate is signed by the next and is within its dates;
   - the intermediates are CAs;
   - the chain ends at an anchor of the type's entitlement (PID, QEAA, PuB-EAA or EAA, per ARF 6.6.3.6);
   - the leaf matches `iss`.
3. **Disclosures:** every digest appears exactly once, recursively; only requested claims are accepted.
4. **KB-JWT:**
   - `typ` is `kb+jwt`;
   - the signature verifies with `cnf.jwk`;
   - `nonce`, `aud` (the client_id), the `iat` window and `sd_hash` match.
5. **Status:** the Token Status List bit, from the trust data.
6. **Mapping:** required claims are present; claims that weren't requested are dropped.

**Failure codes:** `issuer_untrusted`, `signature_invalid`, `disclosure_mismatch`, `nonce_mismatch`, `audience_mismatch`, `credential_expired`, `credential_revoked`, `status_unavailable`, `claim_missing`, `session_expired`, `format_unsupported`. They appear in the request log, the API answer and the callback, never with claim values.

**Credential types for verifiers** come with presets: PID (`urn:eudi:pid:1`, SD-JWT claim names from the PID rulebook), plus custom types (`vct` and claims).

**Step `verifyCredential`:** verifies an SD-JWT VC the client posts directly, for clients with their own wallet integration. It answers with the claims, or 422 with the reason.

## 7. Phase 3: Attestation Provider gateway

**Built-in API *Credential issuance*** (base path `/wallet/issue`, step `walletIssuance`):

| Operation | Caller | Behaviour |
|---|---|---|
| `POST /offers` | provider server (scope `wallet.offers`) | Body `{ credentialType, subject, claims?, txCode? }`. `subject` is the provider server's own reference for the person.<br>Answers `{ offer_id, credential_offer_uri, deep_link: 'openid-credential-offer://…', qr, tx_code? }`. |
| `GET /offers/{id}` | provider server | `pending`, `redeemed` or `expired`, plus the issued credential id(s). |
| `POST /credentials/{id}/revoke`, `/suspend`, `/reinstate` | provider server (scope `wallet.credentials.revoke`) | Flips the status bit. The gateway republishes the list at once. The change is reported to the console so its view and other nodes stay in step. |
| `GET /.well-known/openid-credential-issuer` | wallet, public | Credential Issuer metadata, **signed** with the client's access certificate (ETSI TS 119 472-3). It carries:<br>• the credential configurations;<br>• display information;<br>• the registration certificate;<br>• the embedded disclosure policy, if set;<br>• the endpoints. |
| `GET /.well-known/oauth-authorization-server` | wallet, public | Authorization server metadata: the pre-authorized code grant, the token endpoint, DPoP. |
| `GET /offers/{id}/credential-offer` | wallet, public | The offer JSON. |
| `POST /token` | wallet, public | `pre-authorized_code` (+ `tx_code`). Validates the **wallet attestation** (decision 6). Answers with an access token bound to this offer, DPoP-bound. |
| `POST /nonce` | wallet, public | `c_nonce`. |
| `POST /credential` | wallet (access token) | 1. Checks the proof JWT or key attestation: holder key, nonce, audience.<br>2. **Fetches the claims from the provider server** (`POST {claimsUrl}` with `{ subject, credentialType }` over the OAuth connection), unless the offer carried them.<br>3. Builds the SD-JWT VC (batch issuance when the configuration asks for it): `cnf`, selectively disclosable claims, `status` entry, `x5c` = the issuer certificate.<br>4. Signs with the client's issuer key.<br>5. Answers `{ credentials: [...] }`. |
| `GET /status/{listId}` | public | The client's Token Status List token, signed with the issuer key. |

- **Status indexes** come from ranges the console assigns per node, so no database is needed on the gateway.
- **Records:** `IssuedCredential` rows hold the type, subject reference, status index, issued-at, expiry and claim names, never values.
- **Callback:** the gateway calls the provider server on `offer.redeemed`, `offer.expired` and `credential.issued`.

## 8. Configuration (`schema: 3`, wallet kinds only)

- **API gateways are untouched:** `schema: 2`, the same shape, **the same hashes**.
- Wallet gateways still run the normal pipeline (tokens, subscriptions, rate limits, flows, request log).
- Older gateway software refuses schema 3, so a push fails visibly.

```js
wallet: {
  role: 'issuer' | 'verifier',
  identity: {                         // the client's certificates
    accessCertificateChain, accessKey: { provider, ref } | { provider: 'sealed', privateKey },
    registrationCertificates: [{ id, jwt, intendedUse }],
    issuerCertificateChain?, issuerKey?, qualified?: boolean, legalCategory?: 'QEAA'|'PuB-EAA'|'EAA',
  },
  providerServer: { connectionId, callbackUrl, claimsUrl?, callbackSecret },
  credentialTypes: [{ id, format, vct, claims: [{ path, label, required, selectivelyDisclosable }],
                      anchorSet?, display, validityDays?, batchSize?, keyStorageLevel?, disclosurePolicy? }],
  trust: { walletProviderAnchors?: true },   // the anchors themselves are in the trust data
  sessions: { timeoutSeconds, resultRetentionHours, offerTtlSeconds, store: 'redis' | 'memory' },
  responseModes: ['direct_post.jwt'], allowedOrigins,
}
```

- **Trust data** is kept outside the configuration hash. It holds the anchors per entitlement type, the foreign status lists and the client's own status bits. It goes out with `PUT /v1/trust-data` (push) or the link heartbeat (pull), is cached on disk, and its signatures are checked on the gateway.
- **Problems that block a push:**
  - a missing or expired access certificate;
  - the access certificate SAN not matching the public host (for `x509_san_dns`);
  - a missing registration certificate, or one not covering a configured type or claim;
  - an issuer without a certificate or key;
  - a qualified or PuB-EAA issuer with a sealed key;
  - a credential type without anchors (verifier);
  - no provider-server connection or callback;
  - several nodes without Redis.

## 9. Console

- **Create gateway:** *API gateway*, *Wallet: Attestation Provider*, or *Wallet: Relying Party / Verifier*. The wallet options open a **setup wizard**:
  1. **Organization identity:** legal name, legal category (issuer: QEAA / PuB-EAA / EAA).
  2. **Certificates:**
     - upload the access certificate chain and registration certificate(s), plus the issuer certificate for issuers;
     - the console parses them and shows subject, SAN, validity and the registration's intended uses;
     - add the key reference (KMS / Key Vault / PKCS#11) or a sealed key.
  3. **Credential types:** a PID preset (verifier) or custom types, with the claims editor (claims can be picked from the data dictionary) and the anchor set.
  4. **Provider server:**
     - its URL;
     - its OAuth token endpoint and client data (the new connection type), or mTLS;
     - the callback URL;
     - for issuers, the claims URL.

     **Test connection** gets a token and calls the callback with a test event.
  5. **Nodes:** host, push or pull, as today.
  6. **Done:** the console has created the catalog, the API, the product and the "Provider server" application. It shows the client ID and secret once, and a curl example for `POST /oauth/token` and the first call.
- **Wallet gateway page:** the usual sections, plus tabs:
  - **Identity & certificates:** with expiry warnings at 30 and 7 days, and replace-without-downtime (new chain active from a date).
  - **Credential types**.
  - **Trust anchors:** PEM or list URL, **Refresh now**, status.
  - **Status lists:** foreign lists for verifiers; own lists and ranges for issuers.
  - **Provider server:** connection, callback log, retries.
  - **Verifications** or **Issued credentials:** a metadata log with filters. Issued credentials have **Revoke** and **Suspend**.
- **Application page:** the "Require client certificate" setting (mTLS-bound tokens) and allowed scopes.
- **Connections page:** the new `OAuth 2.0 client credentials` auth type, for every gateway kind.
- **Background:** `services/trustData.js`, started by `server.js` (`TRUST_DATA_REFRESH_MS`, default 5 min; off in tests). It refreshes lists, pushes trust data and hands out status ranges.

**Data model.** New columns go in `scripts/migrate-data.js`; new tables are created on startup.

| | Fields |
|---|---|
| `Gateway` | `kind`, `walletSettings` (JSON) |
| `WalletIdentity` (per gateway) | access certificate chain, key ref / `accessKeySealed`, registration certificates, issuer certificate, issuer key ref / sealed, legal category, qualified |
| `TrustAnchor` | name, entitlement type, source `pem\|list`, PEM, URL, signer certs, status |
| `StatusList` | foreign: URI, token, expiry, status. Own: list id, size, bits, ranges. |
| `CredentialType` | gateway, format, vct, claims, anchor set, display, validity, batch size, key storage level, disclosure policy |
| `Verification`, `IssuedCredential`, `CallbackDelivery` | metadata only |
| `Connection.settings.auth` | new type `oauth2-client-credentials` (token URL, client ID, method, scope, audience); `authSecretSealed` reused; `clientAssertionKeySealed` |
| `Application` | `clientCertificateThumbprint`, `scopes` |
| `UsageRecord.billable` | decision on billing |

- All tenant queries are scoped by `organizationId`; other organizations' records answer 404.
- Serializers never return key material, sealed values, secrets, nonces or claim values.

## 10. Tests

`node:test`, in-memory SQLite, no network. Fixtures are generated at test time: a test CA, access, registration and issuer certificates, a Wallet Provider anchor with a WIA and key attestation, holder keys, SD-JWT VCs, status lists, a fake KMS, and a **fake provider server** (local HTTP with its own OAuth token endpoint).

- **OAuth:**
  - the connection gets, caches and refreshes a token, and retries once on 401;
  - `private_key_jwt` assertions validate;
  - a secret never appears in preview, logs or serializers;
  - an mTLS-bound token used without its certificate gets 401;
  - a missing scope gets 403.
- **Verifier:**
  - PID and a custom type pass end to end: `POST /verifications` → request object (signature, `x5c`, `client_id`, `verifier_info`) → JWE response → callback with HMAC → claims deleted;
  - each of these fails with its code:
    - untrusted chain;
    - wrong entitlement anchor;
    - tampered disclosure;
    - revoked;
    - unknown list;
    - bad nonce;
    - bad audience;
    - expired session;
    - claim outside the registration certificate;
  - the request object is served only once (410 after);
  - mdoc → 501.
- **Issuer:**
  - offer → metadata (signed, with the registration certificate) → token with WIA → nonce → credential, with claims fetched from the fake provider server;
  - the credential passes our own verifier;
  - revoking via the API and via the console flips the bit;
  - each of these fails:
    - an untrusted or missing WIA;
    - a reused nonce;
    - a wrong proof;
    - a redeemed offer;
    - an expired offer;
  - a sealed key on QEAA is refused;
  - status ranges don't overlap across two nodes.
- **Unchanged:**
  - the API-gateway suites pass, with a configuration-hash fixture;
  - tenancy 404s;
  - the migration dry run;
  - `security.test.js`;
  - the docs test, with `docs/plans/` excluded (step 1).

## 11. Docs

- `docs/guides/eu-wallet-gateway.md` covers:
  - the two roles, and what the client brings;
  - the certificates (where to get them: the Access CA, the national registrar);
  - the keys;
  - the wizard;
  - the OAuth setup in both directions;
  - the callbacks and checking them;
  - data protection;
  - what returns 501;
  - the regulatory limits.
- Tutorials:
  - *Verify a PID with your own relying-party certificates*;
  - *Issue a diploma as an attestation provider*.
- Updates:
  - the connections guide (OAuth auth type);
  - the API reference;
  - the security guide;
  - the README;
  - the postmortem summary (kind and counts, no secrets).

## 12. Limits and risks

- **Qualified attestations and signatures:**
  - A QEAA must be signed with the QTSP's key in its certified HSM. The gateway signs through that HSM (PKCS#11 or KMS) and never holds the key.
  - Whether running the issuing service on Phylax infrastructure fits the QTSP's conformity assessment is the **client's** audit question. The docs say so, and offer client-hosted nodes.
- **Certificates are the client's responsibility:** Access CA, registrar and registration certificates per intended use. The gateway checks them but cannot obtain them.
- **501 in this plan:**
  - mdoc;
  - the OpenID4VCI authorization code flow;
  - the browser Digital Credentials API;
  - Phylax as intermediary.
- **Not done:**
  - full RFC 5280 path validation (name constraints, policies, CRL/OCSP of issuer chains);
  - PSD2 SCA `transaction_data` (TS12).

  Both can be follow-ups.
- **Specifications move:** the plan targets OpenID4VP 1.0, OpenID4VCI 1.0, SD-JWT VC, HAIP 1.0 and ARF as of 2026-11. Version-specific parts live in small modules. Before production, the gateway must be tested against the EU reference wallet and the conformance suite (`conformance.eudi.dev`).
- **Size:** several thousand lines across console and gateway, delivered phase by phase, with tests passing after each step.
