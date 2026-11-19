// SD-JWT VC (media type dc+sd-jwt): issuing with selectively disclosable claims, presenting with a
// key-binding JWT (wallets do this; tests use it), and verifying a presentation fail-closed.
// Failure codes match the plan: issuer_untrusted, signature_invalid, disclosure_mismatch,
// nonce_mismatch, audience_mismatch, credential_expired, holder_binding_missing, ...
const crypto = require('crypto');
const {
  WalletError, SIGNING_ALGS, b64u, fromB64u, sha256, parseJson, toKeyObject, signJws, decodeJws, verifySignature,
  certificatesFromX5c, validateChain, certificateNames,
} = require('./jose');

const TYP = 'dc+sd-jwt';
const LEGACY_TYP = 'vc+sd-jwt';
const KB_TYP = 'kb+jwt';
// Registered JWT claims that are never selectively disclosable (SD-JWT VC section 3.2.2).
const FIXED = new Set(['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status', 'iat', 'sub', '_sd', '_sd_alg']);
const TECHNICAL = new Set(['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status', 'iat', '_sd', '_sd_alg']);
const CLOCK_SKEW_SECONDS = 60;
const KB_MAX_AGE_SECONDS = 300;

const digestOf = (disclosure) => b64u(sha256(Buffer.from(disclosure, 'ascii')));

// claims: the credential's claims (top-level ones become disclosable unless listed in `alwaysVisible`).
const issueSdJwt = ({ privateKey, alg, x5c, iss, vct, claims, holderJwk, status, iat, nbf, exp, alwaysVisible = [], decoys = 0 }) => {
  const disclosures = [];
  const digests = [];
  const payload = { iss, vct };
  for (const [name, value] of Object.entries(claims || {})) {
    if (FIXED.has(name)) continue;
    if (alwaysVisible.includes(name)) {
      payload[name] = value;
      continue;
    }
    const disclosure = b64u(JSON.stringify([b64u(crypto.randomBytes(16)), name, value]));
    disclosures.push(disclosure);
    digests.push(digestOf(disclosure));
  }
  for (let count = 0; count < decoys; count += 1) digests.push(b64u(sha256(crypto.randomBytes(32))));
  Object.assign(payload, {
    ...(iat && { iat }),
    ...(nbf && { nbf }),
    ...(exp && { exp }),
    ...(holderJwk && { cnf: { jwk: holderJwk } }),
    ...(status && { status }),
    _sd_alg: 'sha-256',
    _sd: digests.sort(),
  });
  const jwt = signJws({ alg, typ: TYP, ...(x5c && { x5c }) }, payload, privateKey);
  return `${jwt}~${disclosures.map((item) => `${item}~`).join('')}`;
};

// A presentation of `credential` disclosing only `disclose` (claim names), with a key-binding JWT.
const presentSdJwt = (credential, { holderKey, aud, nonce, iat = Math.floor(Date.now() / 1000), disclose, transactionDataHashes }) => {
  const [jwt, ...rest] = credential.split('~');
  const all = rest.filter(Boolean);
  const chosen = disclose ? all.filter((item) => disclose.includes(parseJson(fromB64u(item))[1])) : all;
  const prefix = `${jwt}~${chosen.map((item) => `${item}~`).join('')}`;
  if (!holderKey) return prefix;
  const kb = signJws({ typ: KB_TYP }, {
    iat, aud, nonce, sd_hash: b64u(sha256(Buffer.from(prefix, 'ascii'))),
    ...(transactionDataHashes && { transaction_data_hashes: transactionDataHashes, transaction_data_hashes_alg: 'sha-256' }),
  }, holderKey);
  return `${prefix}${kb}`;
};

// Replaces digests by the disclosed claims, recursively; every disclosure must be used exactly once.
const resolveDisclosures = (payload, disclosures) => {
  const byDigest = new Map();
  for (const disclosure of disclosures) {
    const digest = digestOf(disclosure);
    if (byDigest.has(digest)) throw new WalletError('disclosure_mismatch', 'The same disclosure was sent twice');
    let parsed;
    try {
      parsed = JSON.parse(fromB64u(disclosure).toString('utf8'));
    } catch {
      throw new WalletError('disclosure_mismatch', 'A disclosure cannot be read');
    }
    if (!Array.isArray(parsed) || (parsed.length !== 3 && parsed.length !== 2) || typeof parsed[0] !== 'string') {
      throw new WalletError('disclosure_mismatch', 'A disclosure is not a [salt, name, value] or [salt, value] array');
    }
    byDigest.set(digest, parsed);
  }
  const used = new Set();
  const take = (digest) => {
    if (!byDigest.has(digest)) return null;
    if (used.has(digest)) throw new WalletError('disclosure_mismatch', 'A disclosure digest appears more than once');
    used.add(digest);
    return byDigest.get(digest);
  };
  const walk = (value, depth = 0) => {
    if (depth > 32) throw new WalletError('disclosure_mismatch', 'The credential is nested too deeply');
    if (Array.isArray(value)) {
      const result = [];
      for (const item of value) {
        if (item && typeof item === 'object' && !Array.isArray(item) && Object.keys(item).length === 1 && typeof item['...'] === 'string') {
          const found = take(item['...']);
          if (!found) continue;
          if (found.length !== 2) throw new WalletError('disclosure_mismatch', 'An array element disclosure must be [salt, value]');
          result.push(walk(found[1], depth + 1));
        } else {
          result.push(walk(item, depth + 1));
        }
      }
      return result;
    }
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const [name, item] of Object.entries(value)) {
      if (name === '_sd' || name === '_sd_alg') continue;
      result[name] = walk(item, depth + 1);
    }
    if (value._sd !== undefined) {
      if (!Array.isArray(value._sd)) throw new WalletError('disclosure_mismatch', '_sd must be a list of digests');
      for (const digest of value._sd) {
        const found = take(digest);
        if (!found) continue;
        if (found.length !== 3) throw new WalletError('disclosure_mismatch', 'An object property disclosure must be [salt, name, value]');
        const [, name, disclosed] = found;
        if (typeof name !== 'string' || name === '_sd' || name === '...' || Object.prototype.hasOwnProperty.call(result, name)) {
          throw new WalletError('disclosure_mismatch', 'A disclosure overwrites a claim');
        }
        result[name] = walk(disclosed, depth + 1);
      }
    }
    return result;
  };
  const resolved = walk(payload);
  if (used.size !== byDigest.size) throw new WalletError('disclosure_mismatch', 'A disclosure does not belong to this credential');
  return resolved;
};

// options: { anchors (X509Certificate[]), vcts, nonce, audience, now (ms), requireHolderBinding (default true),
//            requireIssuerName (default true), algs }
// Returns { issuer, vct, claims, status, holderJwk, certificate }.
const verifySdJwtPresentation = (presentation, options) => {
  const now = options.now || Date.now();
  const seconds = Math.floor(now / 1000);
  const algs = options.algs || SIGNING_ALGS;
  if (typeof presentation !== 'string' || !presentation.includes('~')) throw new WalletError('format_unsupported', 'The presentation is not an SD-JWT');
  const parts = presentation.split('~');
  const issuerJwt = parts[0];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(1, -1).filter(Boolean);

  const decoded = decodeJws(issuerJwt);
  const { header, payload } = decoded;
  if (header.typ !== TYP && header.typ !== LEGACY_TYP) throw new WalletError('format_unsupported', `The credential type header is ${String(header.typ).slice(0, 40)}, not ${TYP}`);
  if (!algs.includes(header.alg)) throw new WalletError('signature_invalid', 'The credential is signed with an algorithm that is not accepted');

  const chain = certificatesFromX5c(header.x5c);
  const { leaf } = validateChain(chain, options.anchors, now);
  if (!verifySignature(decoded, leaf.publicKey, algs)) throw new WalletError('signature_invalid', "The issuer's signature does not match");
  if (typeof payload.iss !== 'string') throw new WalletError('issuer_untrusted', 'The credential names no issuer');
  if (options.requireIssuerName !== false && !certificateNames(leaf, payload.iss)) {
    throw new WalletError('issuer_untrusted', "The issuer's certificate does not name the credential's issuer");
  }
  if (options.vcts?.length && !options.vcts.includes(payload.vct)) throw new WalletError('credential_type_mismatch', 'The credential is not of the requested type');
  if (payload.exp !== undefined && !(Number(payload.exp) + CLOCK_SKEW_SECONDS > seconds)) throw new WalletError('credential_expired', 'The credential has expired');
  if (payload.nbf !== undefined && Number(payload.nbf) - CLOCK_SKEW_SECONDS > seconds) throw new WalletError('credential_expired', 'The credential is not valid yet');
  if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') throw new WalletError('format_unsupported', 'Only sha-256 disclosure digests are accepted');

  const resolved = resolveDisclosures(payload, disclosures);

  const holderJwk = payload.cnf?.jwk || null;
  if (options.requireHolderBinding !== false || kbJwt) {
    if (!kbJwt) throw new WalletError('holder_binding_missing', 'The presentation has no key-binding JWT');
    if (!holderJwk) throw new WalletError('holder_binding_missing', 'The credential is not bound to a holder key');
    const kb = decodeJws(kbJwt);
    if (kb.header.typ !== KB_TYP) throw new WalletError('signature_invalid', `The key-binding JWT type is not ${KB_TYP}`);
    let holderKey;
    try {
      holderKey = toKeyObject(holderJwk, 'public');
    } catch {
      throw new WalletError('signature_invalid', 'The holder key in the credential cannot be read');
    }
    if (!verifySignature(kb, holderKey, algs)) throw new WalletError('signature_invalid', "The holder's key-binding signature does not match");
    if (options.nonce !== undefined && kb.payload.nonce !== options.nonce) throw new WalletError('nonce_mismatch', 'The presentation answers another request (nonce)');
    if (options.audience !== undefined && kb.payload.aud !== options.audience) throw new WalletError('audience_mismatch', 'The presentation was made for another verifier (aud)');
    const iat = Number(kb.payload.iat);
    if (!Number.isFinite(iat) || iat > seconds + CLOCK_SKEW_SECONDS || iat < seconds - KB_MAX_AGE_SECONDS) {
      throw new WalletError('presentation_stale', 'The key-binding JWT is not fresh');
    }
    const prefix = `${parts.slice(0, -1).join('~')}~`;
    if (kb.payload.sd_hash !== b64u(sha256(Buffer.from(prefix, 'ascii')))) throw new WalletError('disclosure_mismatch', 'The key-binding JWT does not cover these disclosures (sd_hash)');
  }

  const claims = Object.fromEntries(Object.entries(resolved).filter(([name]) => !TECHNICAL.has(name)));
  return { issuer: payload.iss, vct: payload.vct, claims, status: payload.status || null, holderJwk, certificate: leaf, exp: payload.exp };
};

// Claim path pointers (OpenID4VP section 7): strings select keys, null every array element, integers an index.
const selectPath = (value, path) => {
  let current = [value];
  for (const part of path) {
    const next = [];
    for (const item of current) {
      if (part === null) {
        if (Array.isArray(item)) next.push(...item);
      } else if (typeof part === 'number') {
        if (Array.isArray(item) && part < item.length) next.push(item[part]);
      } else if (item && typeof item === 'object' && !Array.isArray(item) && Object.prototype.hasOwnProperty.call(item, part)) {
        next.push(item[part]);
      }
    }
    current = next;
    if (!current.length) return { found: false };
  }
  return { found: true, value: path.includes(null) ? current : current[0] };
};

// Keeps only the requested claims (by path), in a nested object; a required one that is missing fails.
const pickClaims = (claims, requested) => {
  const result = {};
  for (const claim of requested) {
    const { found, value } = selectPath(claims, claim.path);
    if (!found) {
      if (claim.required !== false) throw new WalletError('claim_missing', `The wallet did not disclose ${claim.path.join('.')}`);
      continue;
    }
    let target = result;
    const keys = claim.path.filter((part) => typeof part === 'string');
    keys.slice(0, -1).forEach((key) => {
      target[key] = target[key] && typeof target[key] === 'object' ? target[key] : {};
      target = target[key];
    });
    target[keys[keys.length - 1]] = value;
  }
  return result;
};

module.exports = { TYP, issueSdJwt, presentSdJwt, verifySdJwtPresentation, resolveDisclosures, selectPath, pickClaims, digestOf };
