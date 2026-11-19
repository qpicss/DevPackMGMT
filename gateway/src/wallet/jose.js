// JOSE with node:crypto only: compact JWS (ES256/ES384/PS256/RS256/EdDSA), JWE with direct
// ECDH-ES key agreement (A128GCM/A256GCM, as OpenID4VP direct_post.jwt uses), and X.509 chain
// checks for x5c headers. No dependencies, so the gateway stays plain JavaScript.
const crypto = require('crypto');

class WalletError extends Error {
  // code: a failure code from the plan (issuer_untrusted, signature_invalid, ...). Never carries claim values.
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const b64u = (value) => Buffer.from(value).toString('base64url');
const b64uJson = (value) => b64u(JSON.stringify(value));
const fromB64u = (value) => Buffer.from(String(value), 'base64url');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
const parseJson = (buffer, code = 'invalid_request', what = 'value') => {
  try {
    return JSON.parse(Buffer.isBuffer(buffer) ? buffer.toString('utf8') : buffer);
  } catch {
    throw new WalletError(code, `The ${what} is not valid JSON`);
  }
};

const ALGS = {
  ES256: { hash: 'sha256', type: 'ec', curve: 'prime256v1' },
  ES384: { hash: 'sha384', type: 'ec', curve: 'secp384r1' },
  PS256: { hash: 'sha256', type: 'rsa', pss: true },
  RS256: { hash: 'sha256', type: 'rsa' },
  EdDSA: { hash: null, type: 'ed25519' },
};
const SIGNING_ALGS = Object.keys(ALGS);

const toKeyObject = (key, kind) => {
  if (key instanceof crypto.KeyObject) return key;
  if (key && typeof key === 'object' && key.kty) return kind === 'private' ? crypto.createPrivateKey({ key, format: 'jwk' }) : crypto.createPublicKey({ key, format: 'jwk' });
  return kind === 'private' ? crypto.createPrivateKey(key) : crypto.createPublicKey(key);
};

// The algorithm a key signs with by default: ES256/ES384 for EC keys, PS256 for RSA, EdDSA for Ed25519.
const algForKey = (key) => {
  const object = key instanceof crypto.KeyObject ? key : toKeyObject(key, key.type === 'private' ? 'private' : 'public');
  const type = object.asymmetricKeyType;
  if (type === 'ec') return object.asymmetricKeyDetails.namedCurve === 'secp384r1' ? 'ES384' : 'ES256';
  if (type === 'rsa' || type === 'rsa-pss') return 'PS256';
  if (type === 'ed25519') return 'EdDSA';
  throw new WalletError('format_unsupported', `Keys of type ${type} can't sign`);
};

// Refuses an algorithm that doesn't fit the key (no algorithm confusion).
const keyFits = (alg, key) => {
  const spec = ALGS[alg];
  if (!spec) return false;
  const type = key.asymmetricKeyType;
  if (spec.type === 'ec') return type === 'ec' && key.asymmetricKeyDetails.namedCurve === spec.curve;
  if (spec.type === 'rsa') return type === 'rsa' || (spec.pss && type === 'rsa-pss');
  return type === spec.type;
};

const signOptions = (alg, key) => {
  const spec = ALGS[alg];
  return {
    key,
    ...(spec.type === 'ec' && { dsaEncoding: 'ieee-p1363' }),
    ...(spec.pss && { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }),
  };
};

const signJws = (header, payload, privateKey) => {
  const key = toKeyObject(privateKey, 'private');
  const alg = header.alg || algForKey(key);
  if (!keyFits(alg, key)) throw new WalletError('signature_invalid', `The key can't sign with ${alg}`);
  const input = `${b64uJson({ ...header, alg })}.${typeof payload === 'string' ? b64u(payload) : b64uJson(payload)}`;
  const signature = crypto.sign(ALGS[alg].hash, Buffer.from(input), signOptions(alg, key));
  return `${input}.${b64u(signature)}`;
};

const decodeJws = (token, code = 'signature_invalid') => {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new WalletError(code, 'Not a compact JWS');
  const header = parseJson(fromB64u(parts[0]), code, 'JWS header');
  const payload = parseJson(fromB64u(parts[1]), code, 'JWS payload');
  return { header, payload, input: `${parts[0]}.${parts[1]}`, signature: fromB64u(parts[2]) };
};

const verifySignature = (decoded, publicKey, algs = SIGNING_ALGS) => {
  const { alg } = decoded.header;
  const key = toKeyObject(publicKey, 'public');
  if (!algs.includes(alg) || !keyFits(alg, key)) return false;
  try {
    return crypto.verify(ALGS[alg].hash, Buffer.from(decoded.input), signOptions(alg, key), decoded.signature);
  } catch {
    return false;
  }
};

// ------------------------------------------------------------------ X.509

const pemToCertificates = (pem) => String(pem || '')
  .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)?.map((block) => new crypto.X509Certificate(block)) || [];

// x5c header value (base64 DER, leaf first) from PEM certificates.
const x5cOf = (certificates) => certificates.map((cert) => cert.raw.toString('base64'));
const certificatesFromX5c = (x5c) => {
  if (!Array.isArray(x5c) || !x5c.length || x5c.length > 10) throw new WalletError('issuer_untrusted', 'The x5c header must list the signing certificate chain');
  try {
    return x5c.map((der) => new crypto.X509Certificate(Buffer.from(String(der), 'base64')));
  } catch {
    throw new WalletError('issuer_untrusted', 'The x5c header holds a certificate that cannot be read');
  }
};

const withinDates = (cert, now) => new Date(cert.validFrom).getTime() <= now && now <= new Date(cert.validTo).getTime();

// Checks that `chain` (leaf first) leads to one of `anchors` (X509Certificate list): each certificate is
// signed by the next and valid now, intermediates are CAs, and the last one is an anchor or is
// signed by one. Returns { leaf, anchor }. Not done (as the plan says): name constraints, policies, CRL/OCSP.
const validateChain = (chain, anchors, now = Date.now()) => {
  if (!anchors?.length) throw new WalletError('issuer_untrusted', 'No trust anchor is configured for this credential type');
  for (let index = 0; index < chain.length; index += 1) {
    const cert = chain[index];
    if (!withinDates(cert, now)) throw new WalletError('issuer_untrusted', `A certificate in the chain is not valid now (${cert.subject.split('\n').join(', ')})`);
    if (index > 0 && !cert.ca) throw new WalletError('issuer_untrusted', 'An intermediate certificate in the chain is not a CA');
    const next = chain[index + 1];
    if (next && !(cert.checkIssued(next) && cert.verify(next.publicKey))) throw new WalletError('issuer_untrusted', 'The certificate chain is broken');
  }
  const last = chain[chain.length - 1];
  const anchor = anchors.find((candidate) => candidate.fingerprint256 === last.fingerprint256)
    || anchors.find((candidate) => candidate.ca && withinDates(candidate, now) && last.checkIssued(candidate) && last.verify(candidate.publicKey));
  if (!anchor) throw new WalletError('issuer_untrusted', 'The certificate chain does not lead to a trusted anchor');
  return { leaf: chain[0], anchor };
};

const sanEntries = (cert) => String(cert.subjectAltName || '').split(/,\s*/).filter(Boolean).map((entry) => {
  const at = entry.indexOf(':');
  return { type: entry.slice(0, at), value: entry.slice(at + 1).replace(/^"|"$/g, '') };
});

// The leaf names the issuer: `iss` is one of its URI SANs, or an https URL whose host is a DNS SAN.
const certificateNames = (cert, iss) => {
  const entries = sanEntries(cert);
  if (entries.some((entry) => entry.type === 'URI' && entry.value === iss)) return true;
  try {
    const url = new URL(iss);
    return url.protocol === 'https:' && entries.some((entry) => entry.type === 'DNS' && entry.value.toLowerCase() === url.hostname.toLowerCase());
  } catch {
    return false;
  }
};

const dnsNames = (cert) => sanEntries(cert).filter((entry) => entry.type === 'DNS').map((entry) => entry.value.toLowerCase());

// ------------------------------------------------------------------ JWE (ECDH-ES, direct)

const CONTENT = { A128GCM: { bits: 128, cipher: 'aes-128-gcm' }, A256GCM: { bits: 256, cipher: 'aes-256-gcm' } };
const lengthPrefixed = (buffer) => {
  const size = Buffer.alloc(4);
  size.writeUInt32BE(buffer.length);
  return Buffer.concat([size, buffer]);
};

// Concat KDF (NIST SP 800-56A) as RFC 7518 4.6.2 uses it; one SHA-256 round covers 128 and 256 bits.
const concatKdf = (secret, enc, apu, apv) => {
  const { bits } = CONTENT[enc];
  const counter = Buffer.from([0, 0, 0, 1]);
  const supp = Buffer.alloc(4);
  supp.writeUInt32BE(bits);
  const digest = sha256(Buffer.concat([counter, secret, lengthPrefixed(Buffer.from(enc)), lengthPrefixed(apu), lengthPrefixed(apv), supp]));
  return digest.subarray(0, bits / 8);
};

const decryptJwe = (token, privateKey) => {
  const parts = String(token || '').split('.');
  if (parts.length !== 5) throw new WalletError('invalid_request', 'The response is not a compact JWE');
  const [protectedB64, encryptedKey, ivB64, ciphertextB64, tagB64] = parts;
  const header = parseJson(fromB64u(protectedB64), 'invalid_request', 'JWE header');
  if (header.alg !== 'ECDH-ES' || encryptedKey) throw new WalletError('invalid_request', 'The response must be encrypted with ECDH-ES');
  if (!CONTENT[header.enc]) throw new WalletError('invalid_request', 'The response uses an unsupported content encryption');
  if (header.zip) throw new WalletError('invalid_request', 'Compressed responses are not accepted');
  let secret;
  try {
    const peer = crypto.createPublicKey({ key: header.epk, format: 'jwk' });
    secret = crypto.diffieHellman({ privateKey: toKeyObject(privateKey, 'private'), publicKey: peer });
  } catch {
    throw new WalletError('invalid_request', 'The response has an unusable ephemeral key');
  }
  const key = concatKdf(secret, header.enc, header.apu ? fromB64u(header.apu) : Buffer.alloc(0), header.apv ? fromB64u(header.apv) : Buffer.alloc(0));
  try {
    const decipher = crypto.createDecipheriv(CONTENT[header.enc].cipher, key, fromB64u(ivB64));
    decipher.setAAD(Buffer.from(protectedB64));
    decipher.setAuthTag(fromB64u(tagB64));
    return { header, plaintext: Buffer.concat([decipher.update(fromB64u(ciphertextB64)), decipher.final()]) };
  } catch {
    throw new WalletError('invalid_request', 'The response could not be decrypted');
  }
};

// What a wallet does; used by tests and kept for completeness.
const encryptJwe = (plaintext, publicJwk, { enc = 'A128GCM', kid, apu, apv } = {}) => {
  const peer = crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
  const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: peer.asymmetricKeyDetails.namedCurve });
  const epk = ephemeral.publicKey.export({ format: 'jwk' });
  const header = { alg: 'ECDH-ES', enc, epk, ...(kid && { kid }), ...(apu && { apu: b64u(apu) }), ...(apv && { apv: b64u(apv) }) };
  const protectedB64 = b64uJson(header);
  const secret = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: peer });
  const key = concatKdf(secret, enc, apu ? Buffer.from(apu) : Buffer.alloc(0), apv ? Buffer.from(apv) : Buffer.alloc(0));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(CONTENT[enc].cipher, key, iv);
  cipher.setAAD(Buffer.from(protectedB64));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return [protectedB64, '', b64u(iv), b64u(ciphertext), b64u(cipher.getAuthTag())].join('.');
};

module.exports = {
  WalletError,
  SIGNING_ALGS,
  b64u,
  b64uJson,
  fromB64u,
  sha256,
  parseJson,
  toKeyObject,
  algForKey,
  signJws,
  decodeJws,
  verifySignature,
  pemToCertificates,
  x5cOf,
  certificatesFromX5c,
  validateChain,
  certificateNames,
  dnsNames,
  decryptJwe,
  encryptJwe,
};
