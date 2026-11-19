# Tutorial 10: Issue diplomas into the EU Wallet

In this tutorial you are **Danube Technical University**. You set up an **EU Wallet: Attestation Provider** gateway that issues your graduates' diplomas into their EUDI Wallets, signed with the university's own issuer key. You also write the small backend that creates offers, supplies the diploma data and revokes a diploma.

Any EUDI-compliant verifier can then check these diplomas, for example the employer's Verifier gateway in [Tutorial 9](09-verify-a-diploma.md). The [EU Wallet overview](../eu-wallet.md) shows both sides together.

**You need:**

- an organization where you are an org admin;
- Docker, to run a gateway node (as in [Tutorial 4](04-run-a-gateway.md));
- Node.js 20 or later for the example backend;
- your certificates, or the test certificates below.

**Time:** about 30 minutes, including the backend.

> **Who can issue with this version?** Attestation providers of the legal category **EAA**. The console stores their keys encrypted (software keys). **QEAA** and **PuB-EAA** providers must sign with a key in an HSM, which comes in a later version. A public university that issues diplomas as a public body (PuB-EAA) is in that group. A university that issues as an EAA, or a TSP that issues EAAs on universities' behalf, can start now.

## How it works

```
 Student portal          University registry (provider server)     Attestation Provider gateway          Graduate's wallet
       │ "Add my diploma to my wallet"  │                                     │                                    │
       ├───────────────────────────────►│ POST /wallet/issue/offers           │                                    │
       │                                ├────────────────────────────────────►│ creates the offer                  │
       │                                │◄── { deep_link, tx_code } ──────────┤                                    │
       │◄── QR code of deep_link ───────┤ tx_code by e-mail or SMS            │                                    │
       │                     (scan)                                           │◄── metadata, offer, token ─────────┤ graduate enters tx_code
       │                                │                                     │◄── POST /credential + key proof ───┤
       │                                │◄── POST claims URL (signed) ────────┤                                    │
       │                                ├── { claims } ──────────────────────►│ signs the SD-JWT VC with the       │
       │                                │                                     │ university's issuer key ──────────►│ diploma stored
       │                                │◄── credential.issued (signed) ──────┤                                    │
       │                                │                                     │                                    │
       │      later: revoke ────────────┤ POST /credentials/{id}/revoke ─────►│ status list updated ◄── verifiers check it
```

The gateway runs OpenID4VCI with the wallet: metadata, the pre-authorized code with a transaction code, DPoP, nonces, the holder's key proofs, signing, and the status list. Your backend creates offers, answers "what is this person's diploma?", and decides on revocations.

## Test certificates for a first try

The university needs three things:

- an **access certificate**, from an Access CA, which signs the issuer metadata;
- an **issuer certificate**, which signs the diplomas. Verifiers trust the CA at the top of its chain;
- a **registration certificate**, from the registrar, stating that the university provides this attestation.

For a first try, make test versions with OpenSSL 3. Real wallets won't trust them, but every console and gateway step works.

```bash
mkdir danube-certs && cd danube-certs
HOST=diplomas.danube-tu.example          # the host of the gateway's public URL

# Test CAs: one for access certificates, one for the university's issuing
for ca in access-ca university-ca; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1825 \
    -keyout $ca.key -out $ca.pem -subj "/CN=Test $ca" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
done

# The access certificate and the issuer certificate, both naming the gateway's host
for leaf in access:access-ca issuer:university-ca; do
  name=${leaf%%:*}; ca=${leaf##*:}
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout $name.key -out $name.csr -subj "/O=Danube Technical University/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST" -addext "keyUsage=critical,digitalSignature"
  openssl x509 -req -in $name.csr -CA $ca.pem -CAkey $ca.key -CAcreateserial \
    -days 365 -copy_extensions copy -out $name.pem
  cat $name.pem $ca.pem > $name-chain.pem
done
```

The issuer certificate must name the issuer: the gateway signs diplomas with `iss` = `https://diplomas.danube-tu.example/wallet/issue`, and verifiers check that the certificate's DNS name is that host.

A stand-in registration certificate (the real format is ETSI TS 119 475):

```bash
node -e '
const crypto = require("crypto"), fs = require("fs");
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const payload = { sub: "Danube Technical University", iat: Math.floor(Date.now() / 1000),
  providesAttestations: [{ format: "dc+sd-jwt", meta: { vct_values: ["https://diplomas.danube-tu.example/credentials/diploma"] } }] };
const input = b64({ alg: "ES256", typ: "JWT" }) + "." + b64(payload);
const signature = crypto.sign("sha256", Buffer.from(input), { key: fs.readFileSync("access-ca.key"), dsaEncoding: "ieee-p1363" });
console.log(input + "." + signature.toString("base64url"));
' > registration.jwt
```

Give `university-ca.pem` to the verifiers who should accept your diplomas. In Tutorial 9 it is Northwind's trust anchor.

## 1. Create the gateway

1. **Gateways → New gateway**:
   - **Name:** `Danube diplomas`
   - **Public URL:** `https://diplomas.danube-tu.example`. This becomes the credential issuer: wallets read `https://diplomas.danube-tu.example/.well-known/openid-credential-issuer/wallet/issue`.
   - **Type:** **EU Wallet: Attestation Provider (OpenID4VCI)**. The type can't be changed later.
2. Create it, then click **Wallet**.

## 2. Add the certificates

In **Identity and certificates**:

1. **Legal name** `Danube Technical University`, **Display name** `Danube TU`, **Legal category** **EAA**.
2. **Access certificate** `access-chain.pem` and its **private key** `access.key`.
3. **Issuer certificate** `issuer-chain.pem` and its **private key** `issuer.key`. Keep them separate from the access certificate: the issuer key signs diplomas, the access key signs metadata.
4. **Registration certificate:** the content of `registration.jwt`.
5. Save. Keys are stored encrypted and never shown again.

## 3. Describe the diploma

In **Credential types**, click **Fill in a diploma (example)**:

| Field | Value |
|---|---|
| Identifier | `diploma`: the `credential_configuration_id` wallets see, and the `credentialType` your backend sends |
| Name | `University diploma` |
| vct | `https://diplomas.danube-tu.example/credentials/diploma`, built from the gateway's public URL |
| Claims | `given_name`, `family_name`, `birthdate?`, `degree`, `field_of_study`, `awarding_institution`, `award_date`, `grade?`, `diploma_number?` |
| Validity | 3650 days |

The preset is an example. If an EU or national rulebook defines a diploma attestation, use its vct and claim names, so that verifiers can rely on them. Publish your vct and claim names to verifiers: Tutorial 9's type must use the same ones.

About **validity**: a diploma doesn't expire, but the credential has a technical validity. Wallets ask for a new one before it ends. Because the validity is longer than 24 hours, every diploma gets an entry in your status list, so you can revoke it.

## 4. Connect your provider server

The provider server is the university registry's backend. In **Provider server**:

1. **Callback URL:** `https://registry.danube-tu.example/wallet/events`. It receives `credential.issued` and `offer.expired`.
2. **Claims URL:** `https://registry.danube-tu.example/wallet/claims`. When a wallet redeems an offer, the gateway asks it for the diploma's claims. Leave it empty if your offers carry the claims.
3. **Connection** (optional): for OAuth 2.0 client credentials or mTLS towards your registry.
4. Save, then **Create callback secret** and copy it. Callbacks and claims requests are both signed with it.

## 5. Set up and run

1. Click **Set up**. It creates the built-in **Wallet issuer** API at `/wallet/issue`, a published product and the application **"Danube diplomas provider server"**. Copy the **client ID** and **client secret**.
2. On the gateway page, add an **HTTPS** port with a certificate for `diplomas.danube-tu.example` from a public CA, and start a node. For a cluster, give the nodes `REDIS_URL`. Each node issues from its own block of the status list, and `GATEWAY_NODE_NAME` must match the node's name in the console.
3. Click **Set up** again to attach the catalog, then **Push configuration**, or turn on **Auto-push**.

Check the metadata:

```bash
curl -s https://diplomas.danube-tu.example/.well-known/openid-credential-issuer/wallet/issue | jq '.credential_configurations_supported | keys'
# [ "diploma" ]
```

## 6. Write the backend

Save it as `danube-registry.js` and run `npm install express qrcode`. It reuses `accessToken()`, `callGateway()` and `validSignature()` from [Tutorial 9](09-verify-a-diploma.md#8-write-the-backend), with `/wallet/issue` in place of `/wallet/verify` in `callGateway`.

```js
// Danube's provider server: offers diplomas, supplies their claims, revokes them.
const express = require('express');
const QRCode = require('qrcode');
// accessToken(), callGateway(method, path, body) and validSignature(header, rawBody): see Tutorial 9.

const students = new Map([          // your student registry in real life
  ['2019-0042', {
    given_name: 'Ana', family_name: 'Popescu', birthdate: '1996-03-14',
    degree: 'Master of Science', field_of_study: 'Structural Engineering',
    awarding_institution: 'Danube Technical University', award_date: '2019-07-12',
    diploma_number: 'DTU-MSC-2019-0042',
  }],
]);
const issued = new Map();           // student -> credential ids, for revocation
const app = express();

// 1. A graduate clicks "Add my diploma to my EU Wallet" in the student portal.
app.post('/students/:id/diploma-offer', async (req, res, next) => {
  try {
    if (!students.has(req.params.id)) return res.sendStatus(404);
    const offer = await callGateway('POST', '/offers', {
      credentialType: 'diploma',
      subject: req.params.id,       // your own reference: it comes back in the claims request
      txCode: true,                 // a 6-digit code the graduate must enter in the wallet
    });
    await sendEmail(req.params.id, `Your code to add your diploma to your wallet: ${offer.tx_code}`);
    res.json({ qr: await QRCode.toDataURL(offer.deep_link), link: offer.deep_link, expiresAt: offer.expires_at });
  } catch (error) {
    next(error);
  }
});

// 2. The wallet redeems the offer: the gateway asks for the claims. Signed like callbacks.
app.post('/wallet/claims', express.raw({ type: 'application/json' }), (req, res) => {
  if (!validSignature(req.get('x-wallet-signature'), req.body)) return res.sendStatus(401);
  const { subject, credentialType } = JSON.parse(req.body);
  const student = students.get(subject);
  if (credentialType !== 'diploma' || !student) return res.sendStatus(404);
  res.json({ claims: student });    // claims that aren't in the type are dropped by the gateway
});

// 3. Events: the diploma is in the wallet, or the offer expired.
app.post('/wallet/events', express.raw({ type: 'application/json' }), (req, res) => {
  if (!validSignature(req.get('x-wallet-signature'), req.body)) return res.sendStatus(401);
  const event = JSON.parse(req.body);
  if (event.event === 'credential.issued') issued.set(event.subject, event.credentialIds);   // e.g. ["1-42"]
  res.sendStatus(204);
});

// 4. The diploma is withdrawn: revoke every copy in the wallet.
app.post('/students/:id/diploma-revocation', async (req, res, next) => {
  try {
    for (const id of issued.get(req.params.id) || []) await callGateway('POST', `/credentials/${id}/revoke`);
    res.sendStatus(204);
  } catch (error) {
    next(error);
  }
});

async function sendEmail(student, text) { /* your mailer */ }

app.listen(8080);
```

Notes:

- **Claims in the offer instead:** send `claims` with `POST /offers` and leave the claims URL empty. The claims URL is better: the data leaves your registry only when the wallet actually redeems the offer.
- **Transaction code:** send `tx_code` through another channel than the QR code, for example by e-mail to the student's verified address. Five wrong codes end the offer.
- **Offers expire** after **Offers expire after** in the Wallet page's settings (24 hours by default). `GET /wallet/issue/offers/{id}` shows `pending`, `redeemed` or `expired`.
- **Batches:** with **Credentials per request** above 1, a wallet receives several copies of the diploma, so that verifiers can't link presentations. `credentialIds` then lists them all. Revoke all of them.
- **Suspend and reinstate** work the same way, with `/suspend` and `/reinstate`. A revoked diploma stays revoked.

## 7. Try it

1. Create an offer for Ana:

   ```bash
   curl -s -X POST http://localhost:8080/students/2019-0042/diploma-offer | jq .link
   ```

   The link looks like `openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fdiplomas.danube-tu.example%2Fwallet%2Fissue%2Fcredential-offer%2F...`.

2. In the wallet, Ana scans the QR code and enters the code from the e-mail. The wallet fetches your metadata (signed with your access certificate), gets a token, proves its key, and receives the diploma signed by your issuer key.
3. Your registry gets `credential.issued` with the credential ids. On the Wallet page, **Issued credentials** lists the diploma: type, subject reference, status-list index and dates, but no claim values.
4. To revoke from the console instead of your backend, click **Revoke** on the diploma in **Issued credentials**. The status list changes on the gateway with the next push, within seconds with auto-push.
5. Verifiers read the list at `https://diplomas.danube-tu.example/wallet/issue/status/1`. After a revocation, Northwind's Verifier gateway refuses the diploma with `credential_revoked`.

With test certificates, real wallets don't trust your metadata. `gateway/test/wallet.test.js` plays a wallet through offer, token, nonce and credential against a real gateway, if you want to see a whole run without one.

## What you have

An Attestation Provider gateway that issues Danube's diplomas into EUDI Wallets under the university's own name and key, takes the data from your registry only when needed, and lets you revoke a diploma at any time.

**Next:** the [reference guide](../guides/eu-wallet-gateway.md) covers wallet attestations (**Require a wallet attestation**), DPoP, every endpoint and the limits of this version.
