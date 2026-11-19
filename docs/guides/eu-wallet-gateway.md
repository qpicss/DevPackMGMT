# EU Wallet gateways: reference

This is the reference: every operation, check, setting and limit. For the business case and the quickest path, start with the [EU Wallet overview](../eu-wallet.md). For step-by-step setups with a complete backend, follow [Tutorial 9: Verify a diploma](../tutorials/09-verify-a-diploma.md) and [Tutorial 10: Issue diplomas](../tutorials/10-issue-diplomas.md).

An EU Wallet gateway works with EU Digital Identity Wallets ([ARF](https://eudi.dev/latest/main/)). It runs for **one client** and in **one role**:

| Type (chosen when the gateway is created) | The client is | The gateway |
|---|---|---|
| **EU Wallet: Relying Party / Verifier** | a relying party | Asks wallets for credentials with OpenID4VP and verifies them. Sends the verified claims to the client's provider server. |
| **EU Wallet: Attestation Provider** | an attestation provider (EAA issuer) | Issues the client's credentials into wallets with OpenID4VCI and signs them with the client's issuer key. Publishes their status list. |

A client who needs both roles gets two gateways. An API gateway stays as it was: its configuration doesn't change.

The client brings only two things:

- **Its certificates**:
  - the **access certificate**, from an Access CA, with its private key;
  - its **registration certificates**, from the registrar;
  - for issuers, the **issuer certificate** with its private key.
- **Its provider server**: the client's own backend.

Every signature a wallet sees is the client's. The gateway runs the protocols and does the cryptography: signing, decryption, validating chains, key binding, and status lists.

The client remains the relying party or issuer of record. The gateway's operator is never shown as the relying party, the issuer, a QTSP or an Access CA.

## Set one up

1. In **Runtime → Gateways**, create a gateway:
   - Choose one of the EU Wallet types.
   - Use the **public URL** the access certificate names. With the `x509_san_dns` client ID, its host must be a DNS name in the certificate.
2. Open its **Wallet** page.
3. Under **Identity and certificates**, paste the following. Private keys are stored encrypted and sent only to the gateway's nodes.
   - the access certificate chain (leaf first) and its private key;
   - the registration certificate (a JWT);
   - for issuers, the issuer certificate and its key.
4. Add the **trust anchors** and **credential types**.
   - **Verifiers:** trust anchors are the CA certificates the issuers you accept chain to: PID providers, QEAA, PuB-EAA or EAA providers. Each credential type names the trust anchors it accepts. **Fill in the EU PID** prefills `urn:eudi:pid:1` with the PID rulebook's claim names.
   - **Issuers:** the identifier of each type is the `credential_configuration_id` wallets see.
5. Under **Provider server**, set:
   - the callback URL;
   - for issuers, the claims URL;
   - optionally a **connection** (below).

   Then create the **callback secret**. It is shown once.
6. Click **Set up**. It creates:
   - the built-in API (`/wallet/verify` or `/wallet/issue`);
   - a published product;
   - the application **"&lt;gateway&gt; provider server"**, with an approved subscription. Its client secret is shown once.

   If the gateway already runs, Set up attaches it to the catalog. Otherwise, start a node first (see [Configuration](configuration.md)) and run Set up again.
7. Add a port and a node as for any gateway, then push.

The page lists anything that still blocks a push, for example an expired certificate, or a type without trust anchors.

## The provider server and OAuth

**The provider server calls the gateway.**

1. It gets a token with OAuth client credentials ([Getting an access token](access-tokens.md)):

   ```bash
   curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials https://console.example.com/oauth/token
   ```

2. It calls the built-in API with `Authorization: Bearer <token>`.

The product's rate limits and usage apply as for any API.

**The gateway calls the provider server** through the connection chosen on the Wallet page. On **Runtime → Connections**, choose the authentication **OAuth 2.0 client credentials** and set:

- the token URL;
- the client ID and secret;
- `client_secret_basic` or `client_secret_post`;
- the scope and audience, if needed.

The gateway gets a token, keeps it until shortly before it expires, and gets a new one when the provider server answers 401. The same connection can also present an mTLS client certificate. API gateways can use this authentication type for any backend.

**Every callback is also signed:**

```
X-Wallet-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" with the callback secret>
```

To check a callback, the provider server:

1. recomputes the HMAC;
2. compares it in constant time;
3. rejects old timestamps.

Callbacks that fail are retried after 5 s, 30 s, 2 min, 10 min and 1 h.

## Verifier: OpenID4VP

| Operation | Called by | What it does |
|---|---|---|
| `POST /wallet/verify/verifications` | provider server | `{ credentialType, claims?, redirectUri?, reference?, match? }` (`match` for KYC types) → `{ id, request_uri, client_id, deep_link, expires_at }`. Show `deep_link` (`openid4vp://…`) as a QR code, or as a link on a phone. Asking for a claim the type doesn't have answers 403 `claim_not_allowed`. |
| `GET /wallet/verify/verifications/{id}` | provider server | `{ status, reason?, issuer?, claims? }`. Claims appear only until the callback has delivered them. Other applications get 404. |
| `GET` or `POST /wallet/verify/request/{id}` | wallet | The request object (`oauth-authz-req+jwt`), described below. It is served once; later calls get 410. |
| `POST /wallet/verify/response/{id}` | wallet | The encrypted response (`direct_post.jwt`, ECDH-ES with A128GCM or A256GCM), or a plain `vp_token` if you chose `direct_post`. |

The request object is signed with the access certificate key. It carries:

- `x5c`: the chain, without the root;
- `client_id`: `x509_san_dns:<host>` or `x509_hash:<hash>`;
- a DCQL query for one `dc+sd-jwt` credential;
- `verifier_info` with the registration certificates;
- the encryption key.

The gateway verifies each presentation as follows and **fails closed**:

- the issuer JWT: `typ` `dc+sd-jwt`, the algorithm, the `vct`, and `nbf`/`exp`;
- the `x5c` chain: up to a trust anchor of the type, and a leaf that names `iss`;
- the signature;
- every disclosure, exactly once;
- the key-binding JWT: holder key, `nonce`, `aud` equal to the `client_id`, freshness, and `sd_hash`;
- the Token Status List entry: fetched over https, checked against the same anchors, and kept for at most five minutes;
- the requested claims: they are present, and anything else is dropped.

A result is `verified` or `failed`, with one of these reasons:

- `issuer_untrusted`
- `signature_invalid`
- `disclosure_mismatch`
- `nonce_mismatch`
- `audience_mismatch`
- `presentation_stale`
- `credential_expired`
- `credential_revoked`
- `status_unavailable`
- `claim_missing`
- `credential_type_mismatch`
- `holder_binding_missing`
- `format_unsupported`
- `wallet_declined`
- for KYC types: `kyc_underage`, `kyc_country_not_allowed`, `kyc_document_expired`, `kyc_data_invalid`

The callback gets `{ event: "verification.completed", id, reference, status, credentialType, issuer, claims }`, plus `kyc` for a KYC type. Once the provider server answers 2xx, the gateway deletes the claims and the KYC evidence. Results that were never delivered are kept for **Keep undelivered results** (24 hours by default).

## KYC: customer due diligence with the PID

A verifier credential type can carry a **KYC profile**, for onboarding customers with the PID. [Tutorial 11](../tutorials/11-kyc-with-the-pid.md) walks through it.

**What a KYC type needs:**

- the required claims `given_name`, `family_name` and `birthdate`, plus `issuing_country` when the countries are limited;
- trust anchors with the entitlement **PID** only. The console refuses other anchors, lists them as a push problem if they appear, and the gateway refuses the configuration.

| Option (`kyc` in the type) | Default | Refused with |
|---|---|---|
| `minimumAge`: 0 to 120, or null | null (no age rule) | `kyc_underage` |
| `allowedCountries`: two-letter codes of the PID's `issuing_country` | `[]` (any) | `kyc_country_not_allowed` |
| `requireValidDocument`: `date_of_expiry`, when disclosed, is not in the past; it is always requested when the type has it | true | `kyc_document_expired` |
| `evidence`: `summary` or `full` | `summary` | |

A `birthdate` that isn't a valid past date fails with `kyc_data_invalid`.

**Starting a KYC verification.** `POST /wallet/verify/verifications` takes an extra `match`: up to 10 claims of the type with the values the provider server holds, for example `{ "family_name": "Stefanescu", "birthdate": "1990-05-01" }`. Values are compared ignoring case, accents, punctuation and spacing. Only types with a KYC profile accept `match`. The claims the rules need, and those in `match`, are always requested.

**The result.** The callback's `kyc` holds:

- `passed`;
- `checks`: each rule that ran, true or false, among `birthdate`, `minimumAge`, `issuingCountry` and `documentValid`;
- `match` and `matched`: whether each value sent in `match` equals the PID. A mismatch doesn't fail the verification;
- `evidence`:
  - `verifiedAt`, `verifier` (the `client_id`), `credentialType`, `vct` and `issuer`;
  - `issuerCertificate`: subject, issuer, serial number, SHA-256 fingerprint and end date;
  - `statusChecked`, `holderBound` and `nonce`;
  - `presentationSha256`;
  - with `full` only, `presentation`: the wallet's presentation, which can be verified again with the PID provider's CA certificate.

A failed rule fails the verification with the reason and `kyc.checks`, and no claims or evidence. `GET /verifications/{id}` shows `kyc` without `evidence` once the claims are delivered. The console records the booleans only.

**Not done by the gateway:** sanctions and PEP screening, risk scoring and record retention. They stay with the obliged entity, which uses the verified claims and the evidence.

## Issuer: OpenID4VCI

| Operation | Called by | What it does |
|---|---|---|
| `POST /wallet/issue/offers` | provider server | `{ credentialType, subject, claims?, txCode? }` → `{ offer_id, credential_offer_uri, deep_link, tx_code? }`. `subject` is your own reference for the person. Give the person `tx_code` through another channel. |
| `GET /wallet/issue/offers/{id}` | provider server | `pending`, `redeemed` or `expired`, with the ids of the issued credentials. |
| `POST /wallet/issue/credentials/{id}/revoke`, `/suspend` or `/reinstate` | provider server | Changes the credential's status-list entry, for example for id `1-42`. A revoked credential stays revoked. |
| `GET /.well-known/openid-credential-issuer/wallet/issue` | wallet | Issuer metadata, with `signed_metadata`: signed with the access certificate and carrying the registration certificates. |
| `GET /.well-known/oauth-authorization-server/wallet/issue` | wallet | Authorization server metadata (pre-authorized code grant, DPoP). |
| `GET /wallet/issue/credential-offer/{id}` | wallet | The offer. |
| `POST /wallet/issue/token` | wallet | Exchanges the pre-authorized code (plus `tx_code`) for an access token, bound with DPoP when the wallet sends a DPoP proof. The code is used once, and five wrong transaction codes end the offer. With **Require a wallet attestation**, it also checks the `OAuth-Client-Attestation` header and its proof against the Wallet Provider anchors. |
| `POST /wallet/issue/nonce` | wallet | Returns a `c_nonce`. |
| `POST /wallet/issue/credential` | wallet | Accepts `proofs.jwt` (`openid4vci-proof+jwt`, with the holder key in `jwk`, `aud` set to the issuer, and the nonce). The response is described below. |
| `GET /wallet/issue/status/{listId}` | anyone | The Token Status List (`statuslist+jwt`, 2 bits per credential), signed with the issuer key. |

For `POST /wallet/issue/credential`, the gateway:

1. fetches the claims from the **claims URL** (`POST { subject, credentialType, offerId }`, which answers `{ claims }`), unless the offer carried them;
2. keeps only the claims of the type;
3. returns one SD-JWT VC per proof, signed with the issuer key, with `cnf`, the status list entry and `x5c`.

Every node issues status indexes from its own block of the list, so nodes never share an index. The console assigns the blocks, and they never move. A pull node's `GATEWAY_NODE_NAME` must match its name in the console. The next index is kept on the node's disk (`wallet-status.json`).

On the Wallet page, **Issued credentials** can be suspended, reinstated or revoked. The change reaches the gateway with the next push, which auto-push starts within seconds. Changes made by the provider server through the API apply on that node at once, and on the others after the console's next push.

## Data protection

- The console stores **metadata only**: type, status, reason, issuer, claim **names**, subject reference and times. It never stores claim values.
- The gateway keeps session state, offers and results in Redis when the node has `REDIS_URL`, otherwise in memory. A gateway with several nodes needs Redis.
- The request log shows the outcome of a wallet operation, never tokens, codes or claims.

## Limits of this version

- **Keys:**
  - Private keys are software keys, sealed in the console and held in the nodes' memory.
  - HSM and cloud KMS keys (AWS KMS, Azure Key Vault, PKCS#11) come in a later version.
  - Until then, the console refuses software keys for **QEAA** and **PuB-EAA** issuers, who must sign in their HSM.
  - Qualified signatures and seals need a QTSP. Whether running a QTSP's issuing service on these nodes fits its conformity assessment is the QTSP's own audit question; nodes can run on the client's machines.
- **Formats and flows:**
  - SD-JWT VC only: mdoc (ISO 18013-5) is not supported.
  - Pre-authorized code only: the authorization code flow, where the person signs in at the issuer, is not supported.
  - No Digital Credentials API: the browser API flow is not supported yet.
- **Trust anchors:** PEM only. Reading EU trusted lists (XML) is not supported yet.
- **Certificate checks:** chains are checked for signatures, dates and CA flags. Name constraints, policies and CRL/OCSP checks of issuer chains are not done.
- **Not covered:** acting as an intermediary for clients without their own access certificate, and PSD2 payment confirmation (ARF TS12).
- **Specifications:** OpenID4VP 1.0, OpenID4VCI 1.0, SD-JWT VC and Token Status List. The `verifier_info` format name of the registration certificate is a setting, because the ecosystem rules still settle it. Before production, test against the EU reference wallet and the conformance suite at `conformance.eudi.dev`.
