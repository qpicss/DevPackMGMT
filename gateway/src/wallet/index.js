// The EU Digital Identity Wallet roles of a wallet gateway (configuration schema 3, `wallet`
// section): 'verifier' (Relying Party, OpenID4VP) or 'issuer' (Attestation Provider, OpenID4VCI).
// The console sends the client's certificates, keys (sealed software keys in this version),
// credential types, trust anchors and provider server; this module validates them (compileWallet)
// and answers the built-in APIs (createWalletService). Events (verifications, offers, issued
// credentials, status changes, callbacks) are drained to the console like usage.
const fs = require('fs');
const path = require('path');
const {
  WalletError, SIGNING_ALGS, b64u, sha256, toKeyObject, algForKey, pemToCertificates, x5cOf, dnsNames,
} = require('./jose');
const { createSessionStore } = require('./sessions');
const { createStatusFetcher, STATUS } = require('./statusList');
const { createProviderClient } = require('./provider');
const { createVerifier } = require('./verifier');
const { createIssuer } = require('./issuer');

const ROLES = ['verifier', 'issuer'];
const BUILTINS = { verifier: 'wallet-verifier', issuer: 'wallet-issuer' };
const CLIENT_ID_SCHEMES = ['x509_san_dns', 'x509_hash'];
const RESPONSE_MODES = ['direct_post.jwt', 'direct_post'];
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_EVENTS = 50000;
const STATE_FILE = 'wallet-status.json';

class WalletConfigError extends Error {}
const assert = (condition, message) => {
  if (!condition) throw new WalletConfigError(message);
};
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const whole = (value, fallback, min, max) => {
  const number = value === undefined || value === null ? fallback : Number(value);
  return Number.isInteger(number) && number >= min && number <= max ? number : null;
};

const loadKey = (key, label) => {
  assert(isObject(key), `${label}: no key is configured`);
  assert(key.provider === 'sealed', `${label}: the key provider "${key.provider}" is not available in this gateway version (sealed keys only)`);
  try {
    return toKeyObject(key.privateKey, 'private');
  } catch {
    throw new WalletConfigError(`${label}: the private key cannot be read`);
  }
};

const loadChain = (pem, label) => {
  let chain;
  try {
    chain = pemToCertificates(pem);
  } catch {
    throw new WalletConfigError(`${label}: a certificate cannot be read`);
  }
  assert(chain.length, `${label}: no certificate is configured`);
  return chain;
};

const keyMatches = (certificate, key) => {
  try {
    return certificate.checkPrivateKey(key);
  } catch {
    return false;
  }
};

// Throws WalletConfigError; `publicUrl` is the gateway's public address.
const compileWallet = (wallet, { publicUrl }) => {
  assert(isObject(wallet), 'A wallet gateway configuration needs a "wallet" section');
  assert(ROLES.includes(wallet.role), 'The wallet role must be verifier or issuer');
  const raw = isObject(wallet.settings) ? wallet.settings : {};
  const settings = {
    clientIdScheme: CLIENT_ID_SCHEMES.includes(raw.clientIdScheme) ? raw.clientIdScheme : 'x509_san_dns',
    responseMode: RESPONSE_MODES.includes(raw.responseMode) ? raw.responseMode : 'direct_post.jwt',
    sessionSeconds: whole(raw.sessionSeconds, 300, 30, 3600),
    resultRetentionHours: whole(raw.resultRetentionHours, 24, 1, 168),
    offerTtlSeconds: whole(raw.offerTtlSeconds, 86400, 60, 30 * 86400),
    batchSize: whole(raw.batchSize, 1, 1, 50),
    requireWalletAttestation: raw.requireWalletAttestation === true,
    verifierInfoFormat: typeof raw.verifierInfoFormat === 'string' && raw.verifierInfoFormat ? raw.verifierInfoFormat.slice(0, 100) : 'registration_cert',
  };
  for (const [name, value] of Object.entries(settings)) assert(value !== null, `The wallet setting ${name} is out of range`);

  const anchors = new Map();
  for (const anchor of Array.isArray(wallet.anchors) ? wallet.anchors : []) {
    assert(isObject(anchor) && ID.test(String(anchor.id)), 'Each trust anchor needs an id');
    anchors.set(anchor.id, { ...anchor, certificates: loadChain(anchor.certificates, `Trust anchor "${anchor.name || anchor.id}"`) });
  }

  const identityRaw = isObject(wallet.identity) ? wallet.identity : {};
  const accessChain = loadChain(identityRaw.accessCertificateChain, 'Access certificate');
  const accessKey = loadKey(identityRaw.accessKey, 'Access certificate key');
  assert(keyMatches(accessChain[0], accessKey), 'The access certificate key does not belong to the access certificate');
  const host = new URL(publicUrl).hostname.toLowerCase();
  let clientId;
  if (settings.clientIdScheme === 'x509_san_dns') {
    assert(dnsNames(accessChain[0]).includes(host), `The access certificate has no DNS name ${host} (the gateway's public address); use the x509_hash client ID or another certificate`);
    clientId = `x509_san_dns:${host}`;
  } else {
    clientId = `x509_hash:${b64u(sha256(accessChain[0].raw))}`;
  }
  const identity = {
    chain: accessChain,
    // The root is not sent (x5c without the trust anchor).
    x5c: x5cOf(accessChain.length > 1 && accessChain[accessChain.length - 1].checkIssued(accessChain[accessChain.length - 1]) ? accessChain.slice(0, -1) : accessChain),
    accessKey,
    accessAlg: algForKey(accessKey),
    clientId,
    subject: typeof identityRaw.legalName === 'string' ? identityRaw.legalName : null,
    registrationCertificates: (Array.isArray(identityRaw.registrationCertificates) ? identityRaw.registrationCertificates : [])
      .filter((item) => isObject(item) && typeof item.jwt === 'string' && item.jwt)
      .map((item) => ({ id: String(item.id || ''), jwt: item.jwt })),
  };

  const types = new Map();
  for (const type of Array.isArray(wallet.credentialTypes) ? wallet.credentialTypes : []) {
    assert(isObject(type) && ID.test(String(type.id)), 'Each credential type needs an id of letters, digits, - or _');
    assert(!types.has(type.id), `Credential type ${type.id} is configured twice`);
    const vcts = (Array.isArray(type.vcts) ? type.vcts : [type.vct]).filter((value) => typeof value === 'string' && value);
    assert(vcts.length, `Credential type ${type.id} needs a vct`);
    const claims = (Array.isArray(type.claims) ? type.claims : []).map((claim) => {
      assert(isObject(claim) && Array.isArray(claim.path) && claim.path.length && claim.path.every((part) => typeof part === 'string' || part === null || Number.isInteger(part)),
        `Credential type ${type.id} has a claim without a valid path`);
      return { path: claim.path, label: typeof claim.label === 'string' ? claim.label : null, required: claim.required !== false };
    });
    assert(claims.length, `Credential type ${type.id} needs at least one claim`);
    const typeAnchors = (Array.isArray(type.anchorIds) ? type.anchorIds : []).flatMap((id) => anchors.get(id)?.certificates || []);
    if (wallet.role === 'verifier') assert(typeAnchors.length, `Credential type ${type.id} has no trust anchor`);
    types.set(type.id, {
      id: type.id,
      name: typeof type.name === 'string' ? type.name : type.id,
      vcts,
      claims,
      anchors: typeAnchors,
      requireIssuerName: type.requireIssuerName !== false,
      validityDays: whole(type.validityDays, 365, 1, 3650) || 365,
      display: isObject(type.display) ? type.display : null,
    });
  }
  assert(types.size, 'Configure at least one credential type');

  const providerRaw = isObject(wallet.provider) ? wallet.provider : {};
  const provider = {
    connectionId: typeof providerRaw.connectionId === 'string' ? providerRaw.connectionId : null,
    callbackUrl: typeof providerRaw.callbackUrl === 'string' && providerRaw.callbackUrl ? providerRaw.callbackUrl : null,
    claimsUrl: typeof providerRaw.claimsUrl === 'string' && providerRaw.claimsUrl ? providerRaw.claimsUrl : null,
    callbackSecret: typeof providerRaw.callbackSecret === 'string' ? providerRaw.callbackSecret : null,
  };
  for (const url of [provider.callbackUrl, provider.claimsUrl].filter(Boolean)) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new WalletConfigError(`The provider server address ${url} is not valid`);
    }
    assert(['http:', 'https:'].includes(parsed.protocol), 'Provider server addresses must use http or https');
  }

  let issuer = null;
  if (wallet.role === 'issuer') {
    const chain = loadChain(identityRaw.issuerCertificateChain, 'Issuer certificate');
    const key = loadKey(identityRaw.issuerKey, 'Issuer key');
    assert(keyMatches(chain[0], key), 'The issuer key does not belong to the issuer certificate');
    const status = isObject(wallet.status) ? wallet.status : {};
    const listSize = whole(status.size, 131072, 1024, 1048576);
    assert(listSize, 'The status list size is out of range');
    assert(ID.test(String(status.listId || '')), 'The status list needs an id');
    issuer = {
      chain,
      x5c: x5cOf(chain.length > 1 && chain[chain.length - 1].checkIssued(chain[chain.length - 1]) ? chain.slice(0, -1) : chain),
      key,
      alg: algForKey(key),
      displayName: typeof identityRaw.displayName === 'string' && identityRaw.displayName ? identityRaw.displayName : (identity.subject || 'Credential issuer'),
      listId: String(status.listId),
      listSize,
      entries: new Map((Array.isArray(status.entries) ? status.entries : [])
        .filter((entry) => Array.isArray(entry) && Number.isInteger(entry[0]) && Object.values(STATUS).includes(entry[1]))
        .map(([index, value]) => [index, value])),
      ranges: isObject(status.ranges) ? status.ranges : {},
      next: isObject(status.next) ? status.next : {},
    };
  }

  const walletProviderAnchors = (Array.isArray(wallet.walletProviderAnchorIds) ? wallet.walletProviderAnchorIds : []).flatMap((id) => anchors.get(id)?.certificates || []);
  if (settings.requireWalletAttestation) assert(walletProviderAnchors.length, 'Wallet attestations are required but no Wallet Provider trust anchor is configured');

  return {
    role: wallet.role,
    builtin: BUILTINS[wallet.role],
    settings,
    algs: SIGNING_ALGS.filter((alg) => alg !== 'RS256'),
    identity,
    issuer,
    types,
    walletProviderAnchors,
    provider,
  };
};

// Hands out status list indexes from the range the console assigned to this node, and remembers
// the next one on disk so a restart never reuses an index.
const createStatusAllocator = ({ dataDir, nodeName, logger }) => {
  const file = dataDir ? path.join(dataDir, STATE_FILE) : null;
  let saved = {};
  try {
    if (file && fs.existsSync(file)) saved = JSON.parse(fs.readFileSync(file, 'utf8')) || {};
  } catch (error) {
    logger.warn('wallet status state unreadable; continuing from the console\'s numbers', { error: error.message });
  }
  let issuer = null;
  let chain = Promise.resolve();
  return {
    nodeName,
    configure(next) {
      issuer = next;
    },
    range() {
      if (!issuer) return null;
      return issuer.ranges[nodeName] || issuer.ranges['*'] || null;
    },
    next() {
      const run = chain.then(async () => {
        const range = this.range();
        if (!Array.isArray(range)) throw new WalletError('status_unavailable', `No status list range is assigned to node ${nodeName}; check its GATEWAY_NODE_NAME matches the console`, 503);
        const [start, end] = range;
        const key = `${issuer.listId}:${start}`;
        const current = Math.max(start, Number(saved[key]) || 0, Number(issuer.next[nodeName] ?? issuer.next['*']) || 0);
        if (current >= end) throw new WalletError('status_unavailable', 'This node has used its whole status list range; the console assigns a new one after the next push', 503);
        saved[key] = current + 1;
        if (file) {
          await fs.promises.mkdir(dataDir, { recursive: true });
          await fs.promises.writeFile(file, JSON.stringify(saved), { mode: 0o600 });
        }
        return current;
      });
      chain = run.catch(() => {});
      return run;
    },
  };
};

class WalletEvents {
  constructor() {
    this.items = [];
    this.dropped = 0;
  }

  push(event) {
    if (this.items.length >= MAX_EVENTS) {
      this.dropped += 1;
      return;
    }
    this.items.push({ time: new Date().toISOString(), ...event });
  }

  drain() {
    const items = this.items;
    this.items = [];
    return items;
  }

  restore(items) {
    this.items = [...items, ...this.items].slice(0, MAX_EVENTS);
  }
}

const createWalletService = ({ settings, connections, logger, nodeName, gatewayId }) => {
  const events = new WalletEvents();
  let sessions = null;
  const statusFetcher = createStatusFetcher({ logger });
  const provider = createProviderClient({ connections, logger, events, ...(settings.walletRetryDelaysMs && { retryDelaysMs: settings.walletRetryDelaysMs }) });
  const statusAllocator = createStatusAllocator({ dataDir: settings.dataDir, nodeName, logger });
  const overlay = new Map();
  let active = null; // { wallet, basePath, handler }

  const configure = (wallet, apis) => {
    if (!wallet) {
      active = null;
      return;
    }
    sessions ||= createSessionStore({ redisUrl: settings.redisUrl, gatewayId, logger });
    const api = apis.find((item) => item.builtin === wallet.builtin);
    statusAllocator.configure(wallet.issuer);
    const deps = { wallet, sessions, statusFetcher, provider, events, statusAllocator, overlay };
    const handler = wallet.role === 'verifier' ? createVerifier(deps) : createIssuer(deps);
    handler.configure?.();
    active = { wallet, basePath: api ? `/${api.basePath.split('/').filter(Boolean).join('/')}` : null, handler };
  };

  const answer = (error) => ({
    status: error.status || 400,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    body: Buffer.from(JSON.stringify({ error: error.code, message: error.message })),
  });

  // A built-in API operation. ctx: { method, operationPath, params, headers, body, clientId }
  const handle = async (ctx, publicUrl, builtin) => {
    if (!active || active.wallet.builtin !== builtin || !active.basePath) {
      return answer(new WalletError('not_configured', 'This gateway is not set up for this wallet API', 503));
    }
    try {
      return await active.handler.handle(ctx, `${publicUrl.replace(/\/+$/, '')}${active.basePath}`);
    } catch (error) {
      if (error instanceof WalletError) return answer(error);
      throw error;
    }
  };

  // The issuer's well-known documents at the host root (OpenID4VCI 1.0 section 12.2.2, RFC 8414):
  // /.well-known/openid-credential-issuer{basePath} and /.well-known/oauth-authorization-server{basePath}.
  const wellKnown = (method, pathname, publicUrl) => {
    if (!active || active.wallet.role !== 'issuer' || !active.basePath || (method !== 'GET' && method !== 'HEAD')) return null;
    const base = `${publicUrl.replace(/\/+$/, '')}${active.basePath}`;
    if (pathname === `/.well-known/openid-credential-issuer${active.basePath}`) return active.handler.metadata(base);
    if (pathname === `/.well-known/oauth-authorization-server${active.basePath}`) return active.handler.authorizationServer(base);
    return null;
  };

  return {
    configure,
    handle,
    wellKnown,
    drain: () => events.drain(),
    restore: (items) => events.restore(items),
    status: () => (active ? {
      role: active.wallet.role,
      clientId: active.wallet.identity.clientId,
      sessions: sessions?.mode || 'memory',
      types: [...active.wallet.types.keys()],
      ...(active.wallet.role === 'issuer' && { statusRange: statusAllocator.range() }),
      ...provider.status(),
    } : null),
    close: async () => {
      await sessions?.close();
    },
  };
};

module.exports = { compileWallet, createWalletService, WalletConfigError, BUILTINS };
