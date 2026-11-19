// KYC (customer due diligence) on a verified PID, for a Relying Party / Verifier credential type
// with a `kyc` profile:
//   - rules on the verified claims: a minimum age, the PID's issuing country, an unexpired document;
//   - matching the provider server's own customer data against the verified claims (reported,
//     never decisive: the obliged entity decides);
//   - evidence an obliged entity keeps for its records: who issued the PID, under which
//     certificate, that its status was checked, the presentation's hash and, with evidence
//     "full", the signed presentation itself so it can be checked again later.
// A failed rule fails the verification with a kyc_* reason and no claims are delivered.
const crypto = require('crypto');

const COUNTRY = /^[A-Z]{2}$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const EVIDENCE = ['summary', 'full'];
const MATCH_LIMIT = 10;
// Claims every KYC profile requests (PID rulebook, SD-JWT VC names).
const BASE_CLAIMS = ['given_name', 'family_name', 'birthdate'];
const REASONS = ['kyc_data_invalid', 'kyc_underage', 'kyc_country_not_allowed', 'kyc_document_expired'];

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const pathKey = (path) => path.join('.');

// The claims (top-level paths) a profile needs, so callers can't narrow them away.
const requiredClaimsOf = (kyc) => [...BASE_CLAIMS, ...(kyc.allowedCountries.length ? ['issuing_country'] : [])];

// raw: the type's `kyc` section; claims: the type's compiled claims. Returns null when KYC is off.
const compileKyc = (raw, typeId, claims, assert) => {
  if (raw === undefined || raw === null || raw === false) return null;
  assert(isObject(raw), `Credential type ${typeId}: kyc must be an object`);
  const minimumAge = raw.minimumAge === undefined || raw.minimumAge === null ? null : Number(raw.minimumAge);
  assert(minimumAge === null || (Number.isInteger(minimumAge) && minimumAge >= 0 && minimumAge <= 120), `Credential type ${typeId}: kyc.minimumAge must be a whole number from 0 to 120`);
  const allowedCountries = Array.isArray(raw.allowedCountries) ? raw.allowedCountries.map((code) => String(code).toUpperCase()) : [];
  assert(allowedCountries.every((code) => COUNTRY.test(code)), `Credential type ${typeId}: kyc.allowedCountries must be two-letter country codes`);
  const evidence = raw.evidence === undefined ? 'summary' : raw.evidence;
  assert(EVIDENCE.includes(evidence), `Credential type ${typeId}: kyc.evidence must be summary or full`);
  const kyc = {
    minimumAge,
    allowedCountries: [...new Set(allowedCountries)],
    requireValidDocument: raw.requireValidDocument !== false,
    evidence,
  };
  for (const name of requiredClaimsOf(kyc)) {
    assert(claims.some((claim) => claim.path.length === 1 && claim.path[0] === name && claim.required !== false),
      `Credential type ${typeId}: KYC needs the required claim ${name}`);
  }
  return kyc;
};

// The provider server's customer data to compare: { "family_name": "Popescu", "address.locality": "Cluj" }.
// Only claims of the type, at most ten, short strings or numbers. Returns { path: value } or throws.
const parseMatch = (raw, type) => {
  if (!isObject(raw)) throw new Error('match must be an object of claim names and expected values');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > MATCH_LIMIT) throw new Error(`match takes 1 to ${MATCH_LIMIT} claims`);
  const result = {};
  for (const [name, value] of entries) {
    const path = name.split('.');
    if (!type.claims.some((claim) => pathKey(claim.path) === pathKey(path))) throw new Error(`match: ${name} is not a claim of ${type.id}`);
    if (!['string', 'number'].includes(typeof value) || String(value).length > 200) throw new Error(`match: ${name} must be a string of at most 200 characters`);
    result[pathKey(path)] = String(value);
  }
  return result;
};

// Case, accents, punctuation and spacing don't count: "Ștefan-Ion " matches "stefan ion".
const normalize = (value) => String(value).normalize('NFKD').replace(/[̀-ͯ]/g, '')
  .toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();

const valueAt = (claims, path) => path.split('.').reduce((current, part) => (isObject(current) ? current[part] : undefined), claims);

const validDate = (text) => {
  const match = DATE.exec(String(text));
  if (!match) return null;
  const date = new Date(`${match[0]}T00:00:00Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== match[0] ? null : match[0];
};

const ageOn = (birthdate, today) => {
  const [by, bm, bd] = birthdate.split('-').map(Number);
  const [ty, tm, td] = today.split('-').map(Number);
  return ty - by - (tm < bm || (tm === bm && td < bd) ? 1 : 0);
};

// claims: every claim the wallet disclosed (verified). Returns { reason, result }; reason is null
// when every rule passed. result holds booleans only, never values.
const evaluateKyc = ({ kyc, claims, match, now = Date.now() }) => {
  const today = new Date(now).toISOString().slice(0, 10);
  const checks = {};
  let reason = null;
  const fail = (code) => {
    reason = reason || code;
  };

  const birthdate = validDate(claims.birthdate);
  checks.birthdate = Boolean(birthdate) && birthdate <= today;
  if (!checks.birthdate) fail('kyc_data_invalid');
  if (kyc.minimumAge !== null) {
    checks.minimumAge = checks.birthdate && ageOn(birthdate, today) >= kyc.minimumAge;
    if (!checks.minimumAge) fail('kyc_underage');
  }
  if (kyc.allowedCountries.length) {
    checks.issuingCountry = kyc.allowedCountries.includes(String(claims.issuing_country || '').toUpperCase());
    if (!checks.issuingCountry) fail('kyc_country_not_allowed');
  }
  if (kyc.requireValidDocument && claims.date_of_expiry !== undefined) {
    const expiry = validDate(claims.date_of_expiry);
    checks.documentValid = Boolean(expiry) && expiry >= today;
    if (!checks.documentValid) fail('kyc_document_expired');
  }

  let matchResult;
  let matched;
  if (match) {
    matchResult = {};
    for (const [path, expected] of Object.entries(match)) {
      const actual = valueAt(claims, path);
      matchResult[path] = actual !== undefined && actual !== null && typeof actual !== 'object' && normalize(actual) === normalize(expected);
    }
    matched = Object.values(matchResult).every(Boolean);
  }
  return { reason, result: { passed: !reason, checks, ...(matchResult && { match: matchResult, matched }) } };
};

// What an obliged entity keeps as proof of the identification. With evidence "full" it also gets
// the presentation exactly as the wallet sent it (issuer-signed SD-JWT, disclosures, key binding).
const buildEvidence = ({ kyc, presentation, verified, session, verifierId, now = Date.now() }) => {
  const certificate = verified.certificate;
  return {
    verifiedAt: new Date(now).toISOString(),
    verifier: verifierId,
    credentialType: session.typeId,
    vct: verified.vct,
    issuer: verified.issuer,
    ...(certificate && {
      issuerCertificate: {
        subject: certificate.subject.split('\n').join(', '),
        issuer: certificate.issuer.split('\n').join(', '),
        serialNumber: certificate.serialNumber,
        fingerprint256: certificate.fingerprint256,
        validTo: new Date(certificate.validTo).toISOString(),
      },
    }),
    statusChecked: Boolean(verified.status),
    holderBound: true,
    nonce: session.nonce,
    presentationSha256: crypto.createHash('sha256').update(presentation).digest('hex'),
    ...(kyc.evidence === 'full' && { presentation }),
  };
};

module.exports = { compileKyc, requiredClaimsOf, parseMatch, evaluateKyc, buildEvidence, normalize, REASONS, MATCH_LIMIT };
