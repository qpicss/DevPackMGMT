// Token Status List (IETF OAuth "Token Status List"): a compressed bit string, one entry per
// credential, published as a signed JWT (typ statuslist+jwt). Index i with `bits` bits per entry
// lives in byte floor(i * bits / 8), starting at the least significant bits.
// Values: 0 valid, 1 invalid (revoked), 2 suspended.
const zlib = require('zlib');
const { WalletError, b64u, fromB64u, signJws, decodeJws, verifySignature, certificatesFromX5c, validateChain } = require('./jose');

const TYP = 'statuslist+jwt';
const STATUS = { valid: 0, revoked: 1, suspended: 2 };
const MAX_CACHE_SECONDS = 300;
const FETCH_TIMEOUT_MS = 5000;
const MAX_LIST_BYTES = 2 * 1024 * 1024;

const encodeList = (size, bits, entries) => {
  const bytes = Buffer.alloc(Math.ceil((size * bits) / 8));
  for (const [index, value] of entries) {
    if (!Number.isInteger(index) || index < 0 || index >= size) continue;
    const bit = index * bits;
    bytes[Math.floor(bit / 8)] |= (value & ((1 << bits) - 1)) << (bit % 8);
  }
  return b64u(zlib.deflateSync(bytes, { level: 9 }));
};

const readEntry = (lst, bits, index) => {
  let bytes;
  try {
    bytes = zlib.inflateSync(fromB64u(lst), { maxOutputLength: 16 * 1024 * 1024 });
  } catch {
    throw new WalletError('status_unavailable', 'The status list cannot be decompressed');
  }
  const bit = index * bits;
  const byte = Math.floor(bit / 8);
  if (byte >= bytes.length) throw new WalletError('status_unavailable', 'The status index is outside the status list');
  return (bytes[byte] >> (bit % 8)) & ((1 << bits) - 1);
};

const signStatusList = ({ uri, size, bits = 2, entries, privateKey, alg, x5c, ttlSeconds = 300, now = Date.now() }) => {
  const iat = Math.floor(now / 1000);
  return signJws({ alg, typ: TYP, ...(x5c && { x5c }) }, {
    sub: uri,
    iat,
    exp: iat + 24 * 3600,
    ttl: ttlSeconds,
    status_list: { bits, lst: encodeList(size, bits, entries) },
  }, privateKey);
};

// Fetches and checks foreign status lists, keeping each for its ttl (at most 5 minutes).
// An unreachable or unverifiable list fails closed with status_unavailable.
const createStatusFetcher = ({ fetchImpl = globalThis.fetch, logger } = {}) => {
  const cache = new Map();
  const allowed = (uri) => {
    try {
      const url = new URL(uri);
      if (url.protocol === 'https:') return true;
      // Plain http only for this machine (tests and local development).
      return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    } catch {
      return false;
    }
  };

  const load = async (uri, anchors, now) => {
    const cached = cache.get(uri);
    if (cached && cached.until > now) return cached;
    let token;
    try {
      const response = await fetchImpl(uri, { headers: { accept: 'application/statuslist+jwt' }, redirect: 'error', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (!response.ok) throw new Error(`status ${response.status}`);
      token = (await response.text()).trim();
      if (token.length > MAX_LIST_BYTES) throw new Error('too large');
    } catch (error) {
      logger?.warn('status list unavailable', { uri, error: error.message });
      throw new WalletError('status_unavailable', 'The status list of the credential could not be fetched');
    }
    const decoded = decodeJws(token, 'status_unavailable');
    if (decoded.header.typ !== TYP) throw new WalletError('status_unavailable', 'The status list has the wrong type');
    let leaf;
    try {
      ({ leaf } = validateChain(certificatesFromX5c(decoded.header.x5c), anchors, now));
    } catch {
      throw new WalletError('status_unavailable', 'The status list is not signed by a trusted issuer');
    }
    if (!verifySignature(decoded, leaf.publicKey)) throw new WalletError('status_unavailable', 'The status list signature does not match');
    const { payload } = decoded;
    if (payload.sub !== uri) throw new WalletError('status_unavailable', 'The status list was published for another address');
    if (payload.exp !== undefined && payload.exp * 1000 < now) throw new WalletError('status_unavailable', 'The status list has expired');
    if (![1, 2, 4, 8].includes(payload.status_list?.bits) || typeof payload.status_list?.lst !== 'string') {
      throw new WalletError('status_unavailable', 'The status list is malformed');
    }
    const ttl = Math.min(MAX_CACHE_SECONDS, Number(payload.ttl) > 0 ? Number(payload.ttl) : MAX_CACHE_SECONDS);
    const entry = { list: payload.status_list, until: Math.min(now + ttl * 1000, payload.exp ? payload.exp * 1000 : Infinity) };
    cache.set(uri, entry);
    if (cache.size > 1000) cache.delete(cache.keys().next().value);
    return entry;
  };

  // `status` is the credential's status claim. Returns 'valid' or throws.
  const check = async (status, anchors, now = Date.now()) => {
    if (!status) return 'valid';
    const reference = status.status_list;
    if (!reference || !Number.isInteger(reference.idx) || reference.idx < 0 || typeof reference.uri !== 'string') {
      throw new WalletError('status_unavailable', 'The credential names a status mechanism this gateway does not know');
    }
    if (!allowed(reference.uri)) throw new WalletError('status_unavailable', 'The status list address is not https');
    const { list } = await load(reference.uri, anchors, now);
    const value = readEntry(list.lst, list.bits, reference.idx);
    if (value === STATUS.revoked) throw new WalletError('credential_revoked', 'The credential has been revoked');
    if (value === STATUS.suspended) throw new WalletError('credential_revoked', 'The credential is suspended');
    if (value !== STATUS.valid) throw new WalletError('credential_revoked', 'The credential is not valid according to its issuer');
    return 'valid';
  };

  return { check, clear: () => cache.clear() };
};

module.exports = { TYP, STATUS, encodeList, readEntry, signStatusList, createStatusFetcher };
