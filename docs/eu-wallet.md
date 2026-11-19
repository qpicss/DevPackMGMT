# EU Digital Identity Wallet gateways

**Accept and issue EU Digital Identity Wallet credentials without building a wallet protocol stack.** You bring your certificates and your own backend. The gateway handles the rest: OpenID4VP and OpenID4VCI, signing, encryption, SD-JWT VC, trust chains, key binding and revocation lists. Your backend makes two REST calls and receives one signed webhook.

Under eIDAS 2, every EU Member State must offer its citizens an EUDI Wallet by the end of 2026 ([ARF](https://eudi.dev/latest/main/)). People will carry their identity data (PID), diplomas, licences, memberships and professional qualifications in it. A business can then do two things with these wallets, and each is a product here:

| The business wants to | Product (gateway type) | EUDI role | Protocol |
|---|---|---|---|
| **Check** what a person shows from their wallet: identity, age, a diploma, a licence, and **KYC** for customer onboarding | **EU Wallet: Relying Party / Verifier** | Relying party | OpenID4VP 1.0 |
| **Put** its own credentials into wallets: diplomas, employee badges, memberships, certificates | **EU Wallet: Attestation Provider** | Attestation provider (EAA issuer), for QTSPs/TSPs and their customers | OpenID4VCI 1.0 |

Both run on the same console and gateway nodes as your APIs, with the same OAuth, products, usage charts, request log, clustering and deployment options.

## A worked example: an employer checks a diploma

Ana applies for an engineering job. The employer, **Northwind Engineering**, must check that she really holds the master's degree on her CV. Today that means a scanned PDF, an email to the university and days of waiting. With the wallet, it takes about ten seconds:

1. Ana's university, **Danube Technical University**, gave her diploma to her wallet when she graduated. It did so through its **Attestation Provider gateway**.
2. On Northwind's careers page, Ana clicks **Verify my diploma with my EU Wallet**. Northwind's HR system asks its **Verifier gateway** for a verification and shows the QR code it gets back.
3. Ana scans the code. Her wallet shows **Northwind Engineering** (from Northwind's own certificates) and the claims it asks for: name, degree, field of study, university, date. She approves.
4. The Verifier gateway checks the answer. The diploma is signed by a university Northwind trusts, it is unchanged, it belongs to Ana's wallet, it is not revoked, and it carries exactly the claims that were asked for.
5. Northwind's HR system receives a signed webhook: `verified`, with the claims. The gateway then deletes them. The application form fills itself in.

### Where the gateways stand

```
 Danube Technical University                                        Northwind Engineering
 ┌────────────────────────┐                                         ┌────────────────────────┐
 │ Student registry        │ "which claims for subject 2019-0042?"   │ HR system               │
 │ (its provider server)   │◄──────────────────┐                     │ (its provider server)   │
 └───────────┬────────────┘                    │                     └───────▲─────────┬──────┘
             │ POST /offers                    │ claims URL     verified claims│         │ POST /verifications
             │ (OAuth token)                   │                (signed webhook)│         │ (OAuth token)
 ┌───────────▼──────────────────────────────┐  │      ┌──────────────────────────┴─────────▼──────┐
 │ ATTESTATION PROVIDER GATEWAY             ├──┘      │ VERIFIER GATEWAY                          │
 │ • OpenID4VCI: offer, token, nonce,        │         │ • signs the request with Northwind's      │
 │   credential endpoints                    │         │   access certificate (JAR + x5c)          │
 │ • checks the holder's key proof (+ DPoP)  │         │ • decrypts the answer (ECDH-ES)           │
 │ • signs the SD-JWT VC with the            │         │ • checks the chain to a trusted anchor,   │
 │   university's issuer key                 │         │   signature, disclosures, key binding,    │
 │ • publishes the status list ◄─────────────┼─────────┼── status list, and the asked-for claims   │
 └───────────────────┬──────────────────────┘ revoked?└──────────────────▲────────────────────────┘
                     │ OpenID4VCI                                        │ OpenID4VP
                     │ (diploma as SD-JWT VC)                            │ (presentation of the diploma)
                     ▼                                                   │
              ┌──────────────────────────────── Ana's EUDI Wallet ───────┴──┐
              │  holds the diploma, shows who asks and for what, Ana approves │
              └──────────────────────────────────────────────────────────────┘
```

- **The gateway stands between the business's backend and the wallet.** The backend never deals with wallet protocols or cryptography. The wallet only ever talks to the gateway, and it sees only the business's own certificates and name.
- **The business stays the relying party or issuer of record.** The gateway operator is never shown as the verifier, the issuer, a QTSP or an Access CA.
- **Each gateway serves one business in one role.** Keys, trust anchors and data of different clients never share a gateway.
- The two sides don't need each other. Northwind's Verifier gateway accepts diplomas from any university whose CA it trusts, whichever product that university uses. Danube's diplomas can be checked by any EUDI-compliant verifier.

The tutorials build exactly this: [Tutorial 9: Verify a diploma](tutorials/09-verify-a-diploma.md) (Northwind) and [Tutorial 10: Issue diplomas](tutorials/10-issue-diplomas.md) (Danube).

## What you bring, what the gateway does

| | The business brings | The gateway does |
|---|---|---|
| **Identity** | Its **access certificate** and key (from an Access CA) and its **registration certificate** (from the national registrar). An issuer also brings its **issuer certificate** and key. | Signs every request, metadata document and credential with them. The wallet shows the business's name, not ours. |
| **Backend** | A **provider server**: any HTTPS service that can call a REST API and receive a webhook. | Runs the whole wallet protocol. Calls the provider server only for what only the business knows: the claims to issue, and what to do with verified claims. |
| **Trust** | The CA certificates of the issuers it accepts (verifier), for example the universities. | Validates every chain, signature, disclosure, key binding and status-list entry, and **fails closed** with a stated reason. |
| **Revocation** | A decision: revoke, suspend or reinstate. | Keeps the Token Status List, signs and publishes it, spreads it across nodes. |
| **Data protection** | Nothing extra. | Asks only for claims the business registered, stores no claim values in the console, and deletes claims from the gateway once delivered. |
| **Access** | One OAuth client, created for it by **Set up**. | Checks the token, the subscription and the rate limit like any API call. Calls back with **OAuth client credentials** and an HMAC signature. |

**Why this matters for the business:**

- **Weeks, not quarters.** No OpenID4VP/VCI library, no JOSE/JWE code, no SD-JWT parser, no status-list service to build, audit and keep current as the specifications move.
- **Small integration.** A verifier integration is two calls (start a verification, and optionally read its result) plus one webhook. An issuer integration is one call (create an offer) plus a claims endpoint.
- **Fail-closed by design.** A credential that can't be fully checked is refused with a reason code, never accepted "for now".
- **Privacy built in.** Claim values never reach the console's database or logs. The gateway asks only for the registered claims.
- **Same operations as your APIs.** Usage charts, request log, metrics, clusters with Redis, push or pull deployment, Docker, systemd, AWS, Azure or offline installation.

**KYC for banks, payment and crypto-asset providers, insurers and other obliged entities:** a KYC profile on a Verifier credential type turns the PID into customer onboarding. The gateway checks age, issuing country and document validity, compares the PID with the data the customer typed, and delivers evidence for your AML records: the issuer's certificate, the status check, a hash of the presentation, and optionally the signed presentation itself. No ID photos, no selfie videos. See [Tutorial 11: KYC with the PID](tutorials/11-kyc-with-the-pid.md).

**For QTSPs and TSPs:** each of your customers gets its own Attestation Provider or Verifier gateway, configured with that customer's certificates, as a product you operate. Your customers keep their name on every credential and every request.

## Up and running in minimal steps

Both roles follow the same five steps. The Wallet page shows them as a checklist with a link to each, and the checklist disappears once all five are done.

### Relying Party / Verifier: check a diploma (or the PID)

| Step | In the console | Time |
|---|---|---|
| 1 | **Gateways → New gateway**: type **EU Wallet: Relying Party / Verifier**, public URL = the host named in your access certificate. Open **Wallet**. | 1 min |
| 2 | **Identity and certificates**: paste the access certificate chain and key, and the registration certificate. | 2 min |
| 3 | **Trust anchors**: add the CA of each university (or PID provider) you accept. | 2 min |
| 4 | **Credential types**: **Fill in a diploma** (or **Fill in the EU PID**), set the vct the issuer publishes, tick its trust anchor. | 2 min |
| 5 | **Provider server**: callback URL, then **Create callback secret**. **Set up**: copy the client ID and secret. On the gateway page: a port, a node, push. | 5 min |

Then, in your backend:

```bash
# 1. a token (cache it: it lasts 10 minutes)
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  https://console.example.com/oauth/token | jq -r .access_token)

# 2. a verification: show deep_link as a QR code
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"credentialType":"diploma","reference":"application-381"}' \
  https://verify.northwind.example/wallet/verify/verifications

# 3. the result arrives at your callback URL as a signed webhook
```

### Attestation Provider: issue diplomas

| Step | In the console | Time |
|---|---|---|
| 1 | **Gateways → New gateway**: type **EU Wallet: Attestation Provider**, public URL = the issuer's host. Open **Wallet**. | 1 min |
| 2 | **Identity and certificates**: legal category **EAA**, the access certificate and key, the issuer certificate and key, the registration certificate. | 3 min |
| 3 | **Credential types**: **Fill in a diploma**, check the vct and claims, set the validity. | 2 min |
| 4 | **Provider server**: callback URL, claims URL (or send claims with each offer), **Create callback secret**. | 2 min |
| 5 | **Set up**: copy the client ID and secret. On the gateway page: an HTTPS port, a node, push. | 5 min |

Then, in your backend:

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"credentialType":"diploma","subject":"2019-0042","txCode":true}' \
  https://diplomas.danube-tu.example/wallet/issue/offers
# → deep_link (show as a QR code) and tx_code (send by SMS or email)
```

The graduate scans the code, enters the transaction code, and the diploma is in the wallet.

## Before production

- **Certificates.** Real access and registration certificates come from your Member State's Access CA and registrar. For a first try, [Tutorial 9](tutorials/09-verify-a-diploma.md#test-certificates-for-a-first-try) shows how to make test certificates. Wallets don't trust test certificates, but every console and gateway step works with them.
- **HTTPS.** Wallets reach the gateway only over HTTPS on the public URL. Use an HTTPS port with a certificate for that host.
- **Conformance.** Test against the EU reference wallet and the conformance suite (`conformance.eudi.dev`) before going live.
- **Limits of this version.** Credentials are SD-JWT VC only (no mdoc). Issuance uses the pre-authorized code flow. Keys are software keys sealed by the console, so qualified (QEAA) and public-body (PuB-EAA) issuers, who must sign in an HSM, wait for HSM/KMS support. A public university that issues diplomas as a PuB-EAA is in that group. The full list is in the [reference guide](guides/eu-wallet-gateway.md#limits-of-this-version).

## Read next

| | |
|---|---|
| [Tutorial 9: Verify a diploma](tutorials/09-verify-a-diploma.md) | The employer's side, from an empty console to a verified diploma in the HR system, with a complete provider server |
| [Tutorial 10: Issue diplomas](tutorials/10-issue-diplomas.md) | The university's side: offers, the claims endpoint, revocation |
| [Tutorial 11: KYC with the PID](tutorials/11-kyc-with-the-pid.md) | Customer onboarding: KYC rules, matching the form data, evidence for AML records |
| [EU Wallet gateways: reference](guides/eu-wallet-gateway.md) | Every operation, check, reason code, setting and limit |
| [Getting an access token](guides/access-tokens.md) | The OAuth client credentials grant the provider server uses |
| [Run a gateway](tutorials/04-run-a-gateway.md) | Ports, nodes and push, in detail |
