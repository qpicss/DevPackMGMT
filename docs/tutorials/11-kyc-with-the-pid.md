# Tutorial 11: Onboard customers with KYC and the EU Wallet

In this tutorial you are **Carpathia Bank**. A new customer opens an account online and proves who they are with the **PID** (person identification data) in their EUDI Wallet, instead of photographing an ID card and recording a selfie video. You add a **KYC profile** to a Relying Party / Verifier gateway, and your onboarding backend gets:

- the verified identification data;
- the outcome of your KYC rules (age, issuing country, valid document);
- whether the data matches what the customer typed in the form;
- **evidence** for your records: who issued the PID, under which certificate, that its revocation status was checked, and, if you choose, the signed presentation itself.

It builds on [Tutorial 9](09-verify-a-diploma.md): the same gateway type, certificates and backend, with a few additions. Read that first if you haven't.

**Time:** about 20 minutes on top of Tutorial 9.

## What the gateway does, and what stays with you

| The gateway | Your bank |
|---|---|
| Asks the wallet for the PID with your access and registration certificates | Decides which data the onboarding needs, and registers it as the intended use with the registrar |
| Verifies it fully: PID provider chain, signature, disclosures, holder binding, nonce, status list | Chooses which PID providers to trust (the national trusted lists) |
| Checks your KYC rules: minimum age, issuing countries, an unexpired document | Sets the rules |
| Compares the PID with the data the customer entered, ignoring case and accents | Decides what to do on a mismatch |
| Delivers claims and evidence once, then deletes them from the gateway | Keeps the records for as long as AML rules require, and runs sanctions and PEP screening, risk scoring and the account decision |

EU anti-money-laundering rules (Regulation (EU) 2024/1624) recognise identification with eIDAS electronic identification means, which include the EUDI Wallet. Whether this check covers all of your customer due diligence is a question for your compliance team: the gateway gives you verified data and proof, not a compliance decision.

## 1. Trust the PID providers

On the Wallet page, in **Trust anchors**, add the CA certificates of the PID providers you accept, with the entitlement **PID**. You find them on the Member States' trusted lists. For a first try, use a test CA as in Tutorial 9.

A KYC type trusts **PID providers only**. The console refuses a KYC type with a QEAA, PuB-EAA or EAA anchor, and the gateway refuses such a configuration.

## 2. Add the KYC credential type

In **Credential types**, click **Fill in KYC (customer onboarding with the PID)**. It fills in:

- **Identifier** `kyc`, **vct** `urn:eudi:pid:1`;
- the claims AML identification usually needs, with the PID rulebook's names:

  | Required | Optional |
  |---|---|
  | `given_name`, `family_name`, `birthdate`, `issuing_country` | `place_of_birth`, `nationalities`, `address.*` (formatted, street, house number, postal code, locality, country), `personal_administrative_number`, `issuing_authority`, `date_of_expiry`, `document_number` |

- every PID trust anchor ticked;
- **Run KYC on this credential** on, with these options:

| Option | What it does | Refusal reason |
|---|---|---|
| **Minimum age** (18) | The customer is at least this old today, from `birthdate` | `kyc_underage` |
| **PIDs issued by** | Only PIDs whose `issuing_country` is in the list, e.g. `RO, DE, FR, IT`. Empty accepts any country your anchors cover. | `kyc_country_not_allowed` |
| **Refuse a PID whose document has expired** | When the PID carries `date_of_expiry`, it must not be in the past. The gateway always asks for `date_of_expiry` when the type has it. | `kyc_document_expired` |
| **Evidence in the callback** | **Summary**, or **Full** (below) | |

A `birthdate` that isn't a real date fails with `kyc_data_invalid`.

Remove the claims you don't need, and keep the list within your registration certificate: wallets show the customer what you ask for. Add the type. The type list shows a **KYC** badge with its rules.

> **Using the API:** `POST /api/org/gateways/:id/wallet/types` with `kyc: { minimumAge: 18, allowedCountries: ["RO","DE"], requireValidDocument: true, evidence: "full" }`. Send `kyc: null` to turn it off.

## 3. Start a KYC verification

Your onboarding backend starts a verification of type `kyc`, as in Tutorial 9. It can also send **`match`**: what the customer typed in the form, to compare with the PID.

```js
const verification = await callGateway('POST', '/verifications', {
  credentialType: 'kyc',
  reference: `onboarding-${applicationId}`,
  match: {                                  // optional; up to 10 claims of the type
    given_name: form.firstName,
    family_name: form.lastName,
    birthdate: form.birthdate,              // YYYY-MM-DD
    'address.postal_code': form.postalCode,
  },
});
// show verification.deep_link as a QR code, or as a button on a phone
```

- The claims the KYC rules need are always requested, even if you narrow `claims`.
- The claims in `match` are added to the request, so they can be compared.
- `match` takes only claims of a type with a KYC profile. Any other claim gets `400`.

## 4. Receive the result

The callback carries a `kyc` section next to the claims:

```json
{
  "event": "verification.completed",
  "id": "Q2x1Zm9y...",
  "reference": "onboarding-5521",
  "status": "verified",
  "credentialType": "kyc",
  "issuer": "https://pid.example-ms.eu",
  "claims": {
    "given_name": "Ioana",
    "family_name": "Ștefănescu",
    "birthdate": "1990-05-01",
    "issuing_country": "RO",
    "date_of_expiry": "2031-01-01",
    "address": { "postal_code": "400001" }
  },
  "kyc": {
    "passed": true,
    "checks": { "birthdate": true, "minimumAge": true, "issuingCountry": true, "documentValid": true },
    "match": { "given_name": true, "family_name": true, "birthdate": true, "address.postal_code": false },
    "matched": false,
    "evidence": {
      "verifiedAt": "2026-11-19T10:42:07.112Z",
      "verifier": "x509_san_dns:onboarding.carpathia-bank.example",
      "credentialType": "kyc",
      "vct": "urn:eudi:pid:1",
      "issuer": "https://pid.example-ms.eu",
      "issuerCertificate": {
        "subject": "CN=PID Provider, O=Example Ministry, C=RO",
        "issuer": "CN=Example PID CA, C=RO",
        "serialNumber": "5A1C…",
        "fingerprint256": "3F:9B:…",
        "validTo": "2028-03-01T00:00:00.000Z"
      },
      "statusChecked": true,
      "holderBound": true,
      "nonce": "dGhlIG5vbmNl…",
      "presentationSha256": "b3c1…",
      "presentation": "eyJhbGciOi…~WyJ…~eyJ0eXAiOiJrYitqd3Qi…"
    }
  }
}
```

- **`kyc.checks`**: each rule that ran, true or false.
- **`kyc.match`** and **`kyc.matched`**: whether each value you sent equals the PID, ignoring case, accents, punctuation and spacing (`Stefanescu` matches `Ștefănescu`). A mismatch **does not fail** the verification. You decide: ask the customer to correct the form, or send the application to manual review.
- **`kyc.evidence`**:
  - `presentationSha256` is the SHA-256 of the presentation exactly as the wallet sent it.
  - With **Full**, `presentation` is that presentation: the PID provider's signed SD-JWT, the disclosures, and the wallet's key-binding JWT over your `nonce` and `verifier`. Anyone with the PID provider's CA certificate can check it again later. That makes it strong evidence, and also personal data: store it as such.
  - With **Summary**, you keep the hash and the certificate details only.

When a rule fails, the callback has `status: "failed"`, a `reason` such as `kyc_underage`, and `kyc.checks` showing which rule failed, but **no claims and no evidence**. The bank receives no identity data for a customer it can't onboard. All the other reasons of Tutorial 9 still apply, for example `credential_revoked` for a revoked PID.

A minimal handler:

```js
if (event.event === 'verification.completed' && event.credentialType === 'kyc') {
  const application = await applications.findByReference(event.reference);
  if (event.status !== 'verified') {
    await application.reject(event.reason);                 // e.g. kyc_underage, credential_revoked
  } else {
    await kycRecords.store({                                 // keep for your AML retention period
      application: application.id,
      identity: event.claims,
      evidence: event.kyc.evidence,
      rules: event.kyc.checks,
    });
    await screening.run(event.claims);                       // sanctions / PEP: your provider
    if (event.kyc.matched === false) await application.sendToReview(event.kyc.match);
    else await application.continue();
  }
}
```

After the 2xx answer, the gateway deletes the claims and the evidence. `GET /wallet/verify/verifications/{id}` then still shows `kyc.passed`, `checks` and `match`, but nothing personal.

## 5. Follow it in the console

On the Wallet page, **Verifications** shows each KYC result, for example `verified · KYC passed · differs from customer data: address.postal_code`, or `failed (kyc_underage) · KYC failed: minimum age`. The console stores the rule and match **booleans** only: no names, dates or evidence.

## What you have

Customer onboarding where the identity is verified cryptographically from the PID, your rules are checked at the gateway, the form data is compared, and you keep proof of how the customer was identified. All of it comes from one call and one callback in your backend.

The [reference guide](../guides/eu-wallet-gateway.md#kyc-customer-due-diligence-with-the-pid) has the full list of KYC options and reasons.
