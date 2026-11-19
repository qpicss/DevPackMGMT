# Tutorial 9: Verify a diploma with the EU Wallet

In this tutorial you are **Northwind Engineering**, an employer. You set up an **EU Wallet: Relying Party / Verifier** gateway, then write the small backend that lets a job candidate prove their university diploma from their EUDI Wallet. At the end, a verified diploma arrives in your HR system as a signed webhook.

The [EU Wallet overview](../eu-wallet.md) explains the business case and where the gateway stands. [Tutorial 10](10-issue-diplomas.md) is the university's side, which issues the diplomas.

**You need:**

- an organization where you are an org admin (see [Tutorial 1](01-publish-your-first-api.md) for the basics of the console);
- Docker, to run a gateway node (as in [Tutorial 4](04-run-a-gateway.md));
- Node.js 20 or later for the example backend;
- your certificates, or the test certificates below.

**Time:** about 30 minutes, including the backend.

## How it works

```
 Candidate's browser          Northwind HR (provider server)          Verifier gateway                    Candidate's wallet
        │ "Verify my diploma"            │                                    │                                    │
        ├───────────────────────────────►│ POST /wallet/verify/verifications  │                                    │
        │                                ├───────────────────────────────────►│ creates a session, signs the       │
        │                                │◄──── { id, deep_link } ────────────┤ request with Northwind's key       │
        │◄──── QR code of deep_link ─────┤                                    │                                    │
        │                     (scan)                                          │◄──── GET /request/{id} ────────────┤
        │                                │                                    ├──── signed request (JAR, x5c) ────►│ shows "Northwind
        │                                │                                    │                                    │ Engineering asks for…"
        │                                │                                    │◄──── encrypted answer ─────────────┤ candidate approves
        │                                │                                    │ decrypts, checks chain, signature, │
        │                                │                                    │ disclosures, key binding, status   │
        │                                │◄─── POST callback (signed) ────────┤                                    │
        │                                ├──── 204 ──────────────────────────►│ deletes the claims                 │
        │◄──── "Diploma verified" ───────┤                                    │                                    │
```

Your backend does three things: it starts a verification, it shows the link as a QR code, and it receives the result. Everything in the middle column is the gateway's work.

## Test certificates for a first try

In production, you get the **access certificate** from your Member State's Access CA, and the **registration certificate** from its registrar. It lists the claims you may ask for, for example the diploma claims for the intended use "recruitment". Skip this section if you have them.

For a first try, make test certificates. Real wallets won't trust them, but the console and the gateway accept them, so you can go through every step. You need OpenSSL 3.

```bash
mkdir northwind-certs && cd northwind-certs
HOST=verify.northwind.example        # the host of the gateway's public URL

# A test CA standing in for the Access CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout access-ca.key -out access-ca.pem -subj "/CN=Test Access CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Northwind's access certificate, naming the gateway's host
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout access.key -out access.csr -subj "/O=Northwind Engineering/CN=$HOST" \
  -addext "subjectAltName=DNS:$HOST" -addext "keyUsage=critical,digitalSignature"
openssl x509 -req -in access.csr -CA access-ca.pem -CAkey access-ca.key -CAcreateserial \
  -days 180 -copy_extensions copy -out access.pem

cat access.pem access-ca.pem > access-chain.pem     # leaf first
```

A stand-in registration certificate: a JWT with the registered intended use, signed by the test CA. The real format is ETSI TS 119 475, issued by the registrar.

```bash
node -e '
const crypto = require("crypto"), fs = require("fs");
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const payload = {
  sub: "Northwind Engineering", iat: Math.floor(Date.now() / 1000),
  intendedUses: [{ purpose: "Recruitment: checking diplomas", credentials: [{ format: "dc+sd-jwt",
    claims: ["given_name","family_name","degree","field_of_study","awarding_institution","award_date"].map((name) => ({ path: [name] })) }] }],
};
const input = b64({ alg: "ES256", typ: "JWT" }) + "." + b64(payload);
const signature = crypto.sign("sha256", Buffer.from(input), { key: fs.readFileSync("access-ca.key"), dsaEncoding: "ieee-p1363" });
console.log(input + "." + signature.toString("base64url"));
' > registration.jwt
```

The **trust anchor** for the diplomas is the CA certificate of the university's issuer. If you also do [Tutorial 10](10-issue-diplomas.md), use its `university-ca.pem`. Otherwise, take the CA certificate the university publishes, or the one on the national trusted list.

## 1. Create the gateway

1. Click **Gateways** in the header.
2. Under **New gateway**, enter:
   - **Name:** `Northwind verifier`
   - **Public URL:** `https://verify.northwind.example`. Wallets fetch the request here. With the default client ID `x509_san_dns`, this host must be a DNS name in the access certificate.
   - **Type:** **EU Wallet: Relying Party / Verifier (OpenID4VP)**. The type can't be changed later.
3. Create it, then click **Wallet** on the gateway page.

The Wallet page opens with **Up and running in five steps**. Each step below ticks one off.

## 2. Add the certificates

In **Identity and certificates**:

1. **Legal name** `Northwind Engineering`, **Display name** `Northwind`.
2. **Access certificate:** paste `access-chain.pem` (leaf first, root included or not). The gateway sends the chain without the root to wallets.
3. **Private key:** paste `access.key`. It must be an unencrypted PEM key (EC P-256/P-384, RSA or Ed25519) that belongs to the certificate. The console stores it encrypted and never shows it again.
4. **Registration certificate:** paste the content of `registration.jwt`. You can add up to 20, one per intended use.
5. Save.

The card now shows the certificate's subject, its DNS names and its end date, with the days left once fewer than 30 remain. An expired access certificate blocks the push.

## 3. Add the university as a trust anchor

In **Trust anchors**, add:

- **Name:** `Danube Technical University`
- **Entitlement:** **EAA**. Use **PuB-EAA** for a public body issuing under public law, **QEAA** for a qualified provider and **PID** for PID providers.
- **Certificates:** the university's CA certificate (`university-ca.pem`).

Add one anchor per university, or per QTSP that issues on behalf of universities. A diploma whose chain doesn't end at one of the anchors chosen for its type is refused with `issuer_untrusted`.

## 4. Describe the diploma

In **Credential types**, click **Fill in a diploma (example)**. It fills in:

| Field | Value |
|---|---|
| Identifier | `diploma`. Your backend uses it in `credentialType`. |
| Name | `University diploma` |
| vct | `https://university.example/credentials/diploma`. **Replace it** with the vct the university's issuer publishes, for example `https://diplomas.danube-tu.example/credentials/diploma` from Tutorial 10. |
| Claims | `given_name`, `family_name`, `birthdate?`, `degree`, `field_of_study`, `awarding_institution`, `award_date`, `grade?`, `diploma_number?` |

A line ending in `?` is an optional claim. Use dotted paths for nested claims, such as `address.locality`.

The preset is an example, not an EU rulebook. When an EU or national rulebook defines a diploma attestation, copy its vct and claim names exactly. Ask only for what your registration certificate covers: wallets compare the request with it and warn the person about anything extra.

Tick **Danube Technical University** under trust anchors, and add the type.

> **Accepting several universities?** Their vct values usually differ. Add one type per vct, for example `diploma-danube` and `diploma-carpathian`. You can also accept the same vct from several anchors by ticking all of them.

## 5. Connect your provider server

The provider server is your HR backend. In **Provider server**:

1. **Callback URL:** `https://hr.northwind.example/wallet/callback`. The gateway node must be able to reach it.
2. **Connection** (optional): choose a connection from **Runtime → Connections** if the callback needs credentials, for example **OAuth 2.0 client credentials** (the gateway gets and renews the token itself) or an mTLS client certificate.
3. Save, then click **Create callback secret** and copy it. It is shown once. Your backend checks every callback with it.

## 6. Set up the API and your backend's login

Click **Set up**. In one step it creates:

- a catalog, with the built-in **Wallet verifier** API at `/wallet/verify`;
- a published product;
- the application **"Northwind verifier provider server"**, subscribed and approved.

Copy the **client ID** and **client secret**: the secret is shown once. Your backend uses them to get tokens.

## 7. Run the gateway

On the gateway page, as in [Tutorial 4](04-run-a-gateway.md):

1. **Connection handlers:** add an **HTTPS** port, for example 443 or 8443. Wallets on phones only trust public certificates, so upload a certificate for `verify.northwind.example` from a public CA. The console's own CA is fine for local tests.
2. **Start a node** with the command the page shows. For a cluster, give the nodes `REDIS_URL`: verification sessions must be shared between nodes.
3. Click **Set up** on the Wallet page again. Now that a node runs, it attaches the gateway to the catalog.
4. **Push configuration**, or turn on **Auto-push**.

All five steps are now ticked. If something still blocks a push, **Before it can be deployed** lists it with a link, for example an access certificate without the gateway's host name.

Check that the gateway answers. Without a token you get a 401:

```bash
curl -i -X POST https://verify.northwind.example/wallet/verify/verifications
```

## 8. Write the backend

This is the whole integration: a token, a call, a QR code and a webhook. Save it as `northwind-hr.js` and run `npm install express qrcode`.

```js
// Northwind's provider server: starts diploma verifications and receives the results.
const crypto = require('node:crypto');
const express = require('express');
const QRCode = require('qrcode');

const CONSOLE_URL = process.env.CONSOLE_URL;               // https://console.example.com
const GATEWAY_URL = process.env.GATEWAY_URL;               // https://verify.northwind.example
const CLIENT_ID = process.env.WALLET_CLIENT_ID;            // from Set up
const CLIENT_SECRET = process.env.WALLET_CLIENT_SECRET;    // from Set up
const CALLBACK_SECRET = process.env.WALLET_CALLBACK_SECRET; // from Create callback secret

// ---- OAuth client credentials: one token, reused until shortly before it expires.
let token = null;
let tokenUntil = 0;
async function accessToken() {
  if (token && Date.now() < tokenUntil) return token;
  const res = await fetch(`${CONSOLE_URL}/oauth/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });
  if (!res.ok) throw new Error(`Token request failed: ${res.status}`);
  const body = await res.json();
  token = body.access_token;
  tokenUntil = Date.now() + (body.expires_in - 60) * 1000;
  return token;
}

async function callGateway(method, path, body) {
  const res = await fetch(`${GATEWAY_URL}/wallet/verify${path}`, {
    method,
    headers: { authorization: `Bearer ${await accessToken()}`, ...(body && { 'content-type': 'application/json' }) },
    ...(body && { body: JSON.stringify(body) }),
  });
  const answer = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Gateway answered ${res.status} ${answer.error || ''}`);
  return answer;
}

// ---- Callbacks are signed: X-Wallet-Signature: t=<seconds>,v1=<hex HMAC-SHA256 of "t.body">
function validSignature(header, rawBody) {
  const parts = Object.fromEntries(String(header || '').split(',').map((part) => part.split('=', 2)));
  const t = Number(parts.t);
  if (!Number.isInteger(t) || Math.abs(Date.now() / 1000 - t) > 300) return false;   // too old or from the future
  if (!/^[0-9a-f]{64}$/.test(parts.v1 || '')) return false;
  const expected = crypto.createHmac('sha256', CALLBACK_SECRET).update(`${parts.t}.`).update(rawBody).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(parts.v1, 'hex'));
}

const applications = new Map();   // your database in real life
const app = express();

// 1. The candidate clicks "Verify my diploma with my EU Wallet".
app.post('/applications/:id/verify-diploma', async (req, res, next) => {
  try {
    const verification = await callGateway('POST', '/verifications', {
      credentialType: 'diploma',
      reference: req.params.id,                 // comes back in the callback
      claims: ['given_name', 'family_name', 'degree', 'field_of_study', 'awarding_institution', 'award_date'],
    });
    applications.set(req.params.id, { verificationId: verification.id, status: 'pending' });
    res.json({
      qr: await QRCode.toDataURL(verification.deep_link),   // on a computer: show the QR code
      link: verification.deep_link,                         // on a phone: a button with this link
      expiresAt: verification.expires_at,
    });
  } catch (error) {
    next(error);
  }
});

// 2. The gateway posts the result. Read the raw body: the signature covers the exact bytes.
app.post('/wallet/callback', express.raw({ type: 'application/json', limit: '1mb' }), (req, res) => {
  if (!validSignature(req.get('x-wallet-signature'), req.body)) return res.sendStatus(401);
  const event = JSON.parse(req.body);
  if (event.event === 'verification.completed') {
    const application = applications.get(event.reference);
    if (application && application.verificationId === event.id) {   // callbacks may be retried: stay idempotent
      Object.assign(application, {
        status: event.status,      // 'verified' or 'failed'
        reason: event.reason,      // when failed, e.g. 'credential_revoked'
        issuer: event.issuer,
        diploma: event.claims,     // only the claims asked for, only when verified
      });
    }
  }
  res.sendStatus(204);             // any 2xx: the gateway deletes the claims
});

// 3. The careers page polls this until the result is in.
app.get('/applications/:id/diploma', (req, res) => {
  const application = applications.get(req.params.id);
  if (!application) return res.sendStatus(404);
  res.json({ status: application.status, reason: application.reason, diploma: application.diploma });
});

app.listen(8080);
```

Notes:

- `claims` narrows the request to the claims you need now. It may only list claims of the type: anything else gets `403 claim_not_allowed`. Leave it out to ask for all the type's claims.
- `redirectUri` (https) sends the person back to your page after a same-device flow on their phone.
- If the callback can't be delivered, the gateway retries after 5 s, 30 s, 2 min, 10 min and 1 h. Meanwhile you can read the result with `GET /wallet/verify/verifications/{id}`. Its claims appear only until a callback has delivered them, and other applications get 404.

## 9. Try it

1. Start a verification for application `381`:

   ```bash
   curl -s -X POST http://localhost:8080/applications/381/verify-diploma | jq .link
   ```

   The link looks like `openid4vp://?client_id=x509_san_dns%3Averify.northwind.example&request_uri=https%3A%2F%2Fverify.northwind.example%2Fwallet%2Fverify%2Frequest%2F...`.

2. Open it with a wallet, or show the QR code. The wallet fetches the signed request, shows **Northwind Engineering** and the six claims, and the candidate approves.
3. Your callback receives:

   ```json
   {
     "event": "verification.completed",
     "id": "Jm4f1Q...",
     "reference": "381",
     "status": "verified",
     "credentialType": "diploma",
     "issuer": "https://diplomas.danube-tu.example/wallet/issue",
     "claims": {
       "given_name": "Ana",
       "family_name": "Popescu",
       "degree": "Master of Science",
       "field_of_study": "Structural Engineering",
       "awarding_institution": "Danube Technical University",
       "award_date": "2019-07-12"
     }
   }
   ```

4. On the Wallet page, **Verifications** lists the result with the claim **names** and the issuer. The console never stores claim values.

With test certificates, real wallets refuse the request, because they don't trust the test Access CA. To see whole runs without a wallet, read `gateway/test/wallet.test.js`. It plays the wallet against real gateways: one test presents a credential to a Verifier gateway end to end, another receives one from an Attestation Provider gateway through offer, token, nonce and credential.

### When a diploma is refused

The callback then carries `status: "failed"` and a `reason`:

| Reason | What it means for the diploma |
|---|---|
| `issuer_untrusted` | Not signed by a university whose CA is a trust anchor of this type |
| `signature_invalid`, `disclosure_mismatch` | Changed after it was issued |
| `credential_revoked` | The university revoked or suspended it |
| `status_unavailable` | The university's status list couldn't be read. The gateway fails closed. |
| `credential_expired` | Outside its validity dates |
| `holder_binding_missing`, `nonce_mismatch`, `audience_mismatch`, `presentation_stale` | Not presented by the wallet it was issued to, or replayed |
| `credential_type_mismatch` | Another vct than the type's |
| `claim_missing` | A required claim wasn't disclosed |
| `wallet_declined` | The person said no |

Show the person a plain message, and let them try again with a new verification.

## What you have

A Verifier gateway that signs with Northwind's certificates, verifies diplomas fully and delivers only the asked-for claims to your HR system. The same gateway can check other credentials: click **Fill in the EU PID** for identity or age checks, and add the PID providers as trust anchors with the entitlement **PID**.

**Next:** [Tutorial 10: Issue diplomas](10-issue-diplomas.md), the university's side. The [reference guide](../guides/eu-wallet-gateway.md) lists every operation, check and setting.
