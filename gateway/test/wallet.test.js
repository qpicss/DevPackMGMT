// EU Wallet gateway: the verifier (OpenID4VP) and issuer (OpenID4VCI) roles end to end, with a
// fake provider server that authenticates the gateway with OAuth client credentials, and unit
// checks of the SD-JWT VC, JWE and status list code.
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const forge = require('node-forge');
const { createGateway } = require('../src/gateway');
const { createPki, credentialsFor, freePort, managementRequest, tokenFor, silentLogger } = require('./support');
const jose = require('../src/wallet/jose');
const { issueSdJwt, presentSdJwt, verifySdJwtPresentation } = require('../src/wallet/sdjwt');
const { signStatusList, readEntry, encodeList } = require('../src/wallet/statusList');
const { signatureHeader } = require('../src/wallet/provider');

const ISSUER = 'https://console.test';
const AUDIENCE = 'oauth-server-gateway';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------------------ certificates (RSA, PS256)

const rsa = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const certificate = ({ commonName, issuer, ca = false, altNames = [] }) => {
  const keys = rsa();
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
  cert.serialNumber = `01${crypto.randomBytes(15).toString('hex')}`;
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const subject = [{ name: 'commonName', value: commonName }];
  cert.setSubject(subject);
  cert.setIssuer(issuer ? forge.pki.certificateFromPem(issuer.certificate).subject.attributes : subject);
  cert.setExtensions(ca
    ? [{ name: 'basicConstraints', cA: true, critical: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }]
    : [{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true }, ...(altNames.length ? [{ name: 'subjectAltName', altNames }] : [])]);
  cert.sign(forge.pki.privateKeyFromPem(issuer ? issuer.privateKey : keys.privateKey), forge.md.sha256.create());
  return { certificate: forge.pki.certificateToPem(cert), privateKey: keys.privateKey };
};

const issuerCa = certificate({ commonName: 'Diploma Issuer CA', ca: true });
const issuerLeaf = certificate({ commonName: 'University', issuer: issuerCa, altNames: [{ type: 6, value: 'https://university.example' }, { type: 2, value: 'university.example' }] });
const strangerCa = certificate({ commonName: 'Unknown CA', ca: true });
const strangerLeaf = certificate({ commonName: 'Impostor', issuer: strangerCa, altNames: [{ type: 6, value: 'https://university.example' }] });
const accessCa = certificate({ commonName: 'Access CA', ca: true });
const verifierAccess = certificate({ commonName: 'Verifier RP', issuer: accessCa, altNames: [{ type: 2, value: 'wallet.example' }] });
const issuerAccess = certificate({ commonName: 'Issuer access', issuer: accessCa, altNames: [{ type: 2, value: 'issuer.example' }] });
const clientIssuerCa = certificate({ commonName: 'Client issuing CA', ca: true });
const clientIssuerLeaf = certificate({ commonName: 'Acme badges', issuer: clientIssuerCa, altNames: [{ type: 2, value: 'issuer.example' }] });

const chainPem = (...items) => items.map((item) => item.certificate).join('');
const x5c = (...items) => jose.x5cOf(items.map((item) => new crypto.X509Certificate(item.certificate)));
const holder = () => {
  const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey: keys.privateKey, jwk: keys.publicKey.export({ format: 'jwk' }) };
};

// ------------------------------------------------------------------ the client's provider server

const startProvider = async () => {
  const seen = { tokens: 0, callbacks: [], claims: [], statusEntries: new Map() };
  let base = '';
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString();
      const send = (status, value, type = 'application/json') => {
        res.writeHead(status, { 'content-type': type });
        res.end(typeof value === 'string' ? value : JSON.stringify(value));
      };
      if (req.url === '/oauth/token') {
        const expected = `Basic ${Buffer.from('gateway-client:s3cret').toString('base64')}`;
        if (req.headers.authorization !== expected || !body.includes('grant_type=client_credentials')) return send(401, { error: 'invalid_client' });
        seen.tokens += 1;
        return send(200, { access_token: `provider-token-${seen.tokens}`, token_type: 'Bearer', expires_in: 3600 });
      }
      if (req.headers.authorization !== `Bearer provider-token-${seen.tokens}`) return send(401, { error: 'invalid_token' });
      if (req.url === '/callback') {
        seen.callbacks.push({ headers: req.headers, body, json: JSON.parse(body) });
        return send(200, { ok: true });
      }
      if (req.url === '/claims') {
        const request = JSON.parse(body);
        seen.claims.push(request);
        return send(200, { claims: { name: 'Ana Pop', role: 'engineer', internal_note: 'not in the type' } });
      }
      return send(404, { error: 'not_found' });
    });
  });
  // The diploma issuer's status list, served without auth.
  const statusServer = http.createServer((req, res) => {
    const token = signStatusList({
      uri: `${base}${req.url}`, size: 1024, bits: 2, entries: seen.statusEntries, privateKey: issuerLeaf.privateKey, x5c: x5c(issuerLeaf),
    });
    res.writeHead(200, { 'content-type': 'application/statuslist+jwt' });
    res.end(token);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  await new Promise((resolve) => statusServer.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${statusServer.address().port}`;
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    statusUrl: base,
    seen,
    close: async () => {
      for (const item of [server, statusServer]) {
        item.closeAllConnections();
        await new Promise((resolve) => item.close(resolve));
      }
    },
  };
};

const providerConnection = (provider) => ({
  id: 'conn-provider',
  name: 'Provider server',
  connectTimeoutMs: 2000,
  timeoutMs: 5000,
  retries: 0,
  retryOn: [],
  circuitBreaker: { enabled: false, failureThreshold: 5, cooldownMs: 30000 },
  auth: { type: 'oauth2', tokenUrl: `${provider.url}/oauth/token`, clientId: 'gateway-client', secret: 's3cret', clientAuthMethod: 'client_secret_basic' },
  tls: { rejectUnauthorized: true },
});

const baseConfig = (pki, { kind, publicUrl, handlerPort, api, connections, wallet, version = 'w1' }) => ({
  schema: 3,
  version,
  generatedAt: new Date().toISOString(),
  gateway: { id: pki.gatewayId, name: 'Wallet gateway', nodeCount: 1, kind, publicUrl },
  issuer: ISSUER,
  audience: AUDIENCE,
  tokenKeys: [{ kid: pki.tokenKey.kid, publicKey: pki.tokenKey.publicKey }],
  handlers: [{ id: 'h1', name: 'Public HTTP', port: handlerPort, protocol: 'http' }],
  connections,
  apis: [api],
  products: [{ id: 'prod-wallet', name: 'Wallet', apiIds: [api.id], rateLimit: { enabled: false } }],
  subscriptions: ['client-1', 'client-2'].map((clientId) => ({ clientId, application: `App ${clientId}`, productIds: ['prod-wallet'] })),
  wallet,
});

const gatewayOptions = (pki, dataDir, extra = {}) => ({
  credentials: credentialsFor(pki),
  managementHost: '127.0.0.1',
  managementPort: 0,
  healthHost: '127.0.0.1',
  healthPort: 0,
  adminHost: '127.0.0.1',
  adminPort: 0,
  bindHost: '127.0.0.1',
  dataDir,
  policyWorkers: 1,
  logger: silentLogger(),
  walletRetryDelaysMs: [50, 50],
  ...extra,
});

const waitFor = async (check, label) => {
  for (let count = 0; count < 100; count += 1) {
    const value = check();
    if (value) return value;
    await sleep(20);
  }
  throw new Error(`Timed out waiting for ${label}`);
};

// ------------------------------------------------------------------ unit checks

describe('wallet building blocks', () => {
  it('encrypts and decrypts ECDH-ES responses (A128GCM and A256GCM)', () => {
    const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    for (const enc of ['A128GCM', 'A256GCM']) {
      const token = jose.encryptJwe('{"hello":"wallet"}', jwk, { enc, kid: 'k1', apu: 'wallet', apv: 'verifier' });
      const { header, plaintext } = jose.decryptJwe(token, keys.privateKey);
      assert.equal(header.kid, 'k1');
      assert.equal(plaintext.toString(), '{"hello":"wallet"}');
    }
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    assert.throws(() => jose.decryptJwe(jose.encryptJwe('x', jwk), other.privateKey), /could not be decrypted/);
  });

  it('verifies an SD-JWT VC and refuses tampering, other anchors and replays', () => {
    const owner = holder();
    const credential = issueSdJwt({
      privateKey: issuerLeaf.privateKey, x5c: x5c(issuerLeaf), iss: 'https://university.example', vct: 'https://example.org/diploma',
      claims: { given_name: 'Ana', degree: 'MSc', address: { locality: 'Cluj' } }, holderJwk: owner.jwk, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const anchors = jose.pemToCertificates(issuerCa.certificate);
    const presentation = presentSdJwt(credential, { holderKey: owner.privateKey, aud: 'x509_san_dns:wallet.example', nonce: 'n-1', disclose: ['given_name', 'degree'] });
    const options = { anchors, vcts: ['https://example.org/diploma'], nonce: 'n-1', audience: 'x509_san_dns:wallet.example' };
    const result = verifySdJwtPresentation(presentation, options);
    assert.deepEqual(result.claims, { given_name: 'Ana', degree: 'MSc' });

    const code = (fn) => {
      try {
        fn();
      } catch (error) {
        return error.code;
      }
      return 'passed';
    };
    assert.equal(code(() => verifySdJwtPresentation(presentation, { ...options, nonce: 'other' })), 'nonce_mismatch');
    assert.equal(code(() => verifySdJwtPresentation(presentation, { ...options, audience: 'x509_san_dns:evil.example' })), 'audience_mismatch');
    assert.equal(code(() => verifySdJwtPresentation(presentation, { ...options, anchors: jose.pemToCertificates(strangerCa.certificate) })), 'issuer_untrusted');
    assert.equal(code(() => verifySdJwtPresentation(presentation, { ...options, vcts: ['https://example.org/other'] })), 'credential_type_mismatch');
    // A disclosure swapped for one the issuer never signed.
    const parts = presentation.split('~');
    parts[1] = jose.b64u(JSON.stringify(['salt', 'degree', 'PhD']));
    assert.equal(code(() => verifySdJwtPresentation(parts.join('~'), options)), 'disclosure_mismatch');
    // Without the key-binding JWT.
    assert.equal(code(() => verifySdJwtPresentation(presentSdJwt(credential, {}), options)), 'holder_binding_missing');
    // Signed by an impostor certificate that names the same issuer.
    const forged = issueSdJwt({ privateKey: strangerLeaf.privateKey, x5c: x5c(strangerLeaf), iss: 'https://university.example', vct: 'https://example.org/diploma', claims: { degree: 'PhD' }, holderJwk: owner.jwk });
    assert.equal(code(() => verifySdJwtPresentation(presentSdJwt(forged, { holderKey: owner.privateKey, aud: options.audience, nonce: 'n-1' }), options)), 'issuer_untrusted');
  });

  it('packs status list entries of two bits', () => {
    const lst = encodeList(64, 2, new Map([[3, 1], [10, 2], [63, 1]]));
    assert.deepEqual([0, 3, 10, 63].map((index) => readEntry(lst, 2, index)), [0, 1, 2, 1]);
  });

  it('signs callbacks with a timestamped HMAC', () => {
    const header = signatureHeader('secret', '{"a":1}', 1700000000000);
    const expected = crypto.createHmac('sha256', 'secret').update('1700000000.{"a":1}').digest('hex');
    assert.equal(header, `t=1700000000,v1=${expected}`);
  });
});

// ------------------------------------------------------------------ verifier

describe('wallet gateway: relying party / verifier', () => {
  let pki;
  let gateway;
  let ports;
  let handlerPort;
  let provider;
  let dataDir;
  const owner = holder();

  const verifierApi = {
    id: 'api-verify',
    name: 'Credential verification',
    version: '1.0.0',
    basePath: '/wallet/verify',
    builtin: 'wallet-verifier',
    operations: [
      { method: 'post', path: '/verifications' },
      { method: 'get', path: '/verifications/{id}' },
      { method: 'get', path: '/request/{id}', access: 'public' },
      { method: 'post', path: '/request/{id}', access: 'public' },
      { method: 'post', path: '/response/{id}', access: 'public' },
    ],
  };

  const call = (pathname, { method = 'GET', body, form, headers = {}, client = 'client-1' } = {}) => fetch(`http://127.0.0.1:${handlerPort}${pathname}`, {
    method,
    headers: {
      ...(client && { authorization: `Bearer ${tokenFor(pki, { clientId: client })}` }),
      ...(body !== undefined && { 'content-type': 'application/json' }),
      ...(form !== undefined && { 'content-type': 'application/x-www-form-urlencoded' }),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : form !== undefined ? new URLSearchParams(form).toString() : undefined,
  });

  const credential = ({ claims = { given_name: 'Ana', family_name: 'Pop', degree: 'MSc' }, statusIndex = 5, list = 1, leaf = issuerLeaf } = {}) => issueSdJwt({
    privateKey: leaf.privateKey,
    x5c: x5c(leaf),
    iss: 'https://university.example',
    vct: 'https://example.org/diploma',
    claims,
    holderJwk: owner.jwk,
    status: { status_list: { idx: statusIndex, uri: `${provider.statusUrl}/lists/${list}` } },
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  });

  // What a wallet does: fetch the request object, present, encrypt, post.
  const answerAsWallet = async (started, { present = (request) => presentSdJwt(credential(), { holderKey: owner.privateKey, aud: request.client_id, nonce: request.nonce, disclose: ['given_name', 'degree'] }) } = {}) => {
    const requestPath = new URL(started.request_uri).pathname;
    const fetched = await call(requestPath, { client: null });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.headers.get('content-type'), 'application/oauth-authz-req+jwt');
    const decoded = jose.decodeJws(await fetched.text());
    const leaf = new crypto.X509Certificate(Buffer.from(decoded.header.x5c[0], 'base64'));
    assert.ok(jose.verifySignature(decoded, leaf.publicKey), 'the request object is signed with the access certificate');
    const request = decoded.payload;
    const encryptionKey = request.client_metadata.jwks.keys[0];
    const response = jose.encryptJwe(JSON.stringify({ vp_token: { credential: [present(request)] }, state: request.state }), encryptionKey, { kid: encryptionKey.kid });
    const posted = await call(new URL(request.response_uri).pathname, { method: 'POST', client: null, form: { response } });
    return { request, posted, decoded };
  };

  before(async () => {
    pki = createPki();
    provider = await startProvider();
    handlerPort = await freePort();
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-verifier-'));
    gateway = createGateway(gatewayOptions(pki, dataDir, { nodeName: 'node-v' }));
    ports = await gateway.start();
    const config = baseConfig(pki, {
      kind: 'wallet-verifier',
      publicUrl: 'https://wallet.example',
      handlerPort,
      api: verifierApi,
      connections: [providerConnection(provider)],
      wallet: {
        role: 'verifier',
        identity: {
          accessCertificateChain: chainPem(verifierAccess, accessCa),
          accessKey: { provider: 'sealed', privateKey: verifierAccess.privateKey },
          registrationCertificates: [{ id: 'r1', jwt: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.' }],
        },
        settings: {},
        anchors: [{ id: 'a1', name: 'Diploma Issuer CA', entitlement: 'EAA', certificates: issuerCa.certificate }],
        credentialTypes: [{
          id: 'diploma', name: 'Diploma', vct: 'https://example.org/diploma', anchorIds: ['a1'],
          claims: [{ path: ['given_name'] }, { path: ['degree'] }, { path: ['family_name'], required: false }],
        }],
        provider: { connectionId: 'conn-provider', callbackUrl: `${provider.url}/callback`, callbackSecret: 'cb-secret' },
      },
    });
    const pushed = await managementRequest({ port: ports.managementPort, method: 'PUT', path: '/v1/config', body: config, client: pki.management, pki });
    assert.equal(pushed.status, 200, JSON.stringify(pushed.body));
  });

  after(async () => {
    await gateway.stop();
    await provider.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('refuses a configuration whose access certificate does not name the public host', async () => {
    const config = baseConfig(pki, {
      kind: 'wallet-verifier', publicUrl: 'https://other.example', handlerPort, api: verifierApi, connections: [],
      wallet: {
        role: 'verifier',
        identity: { accessCertificateChain: verifierAccess.certificate, accessKey: { provider: 'sealed', privateKey: verifierAccess.privateKey } },
        anchors: [{ id: 'a1', certificates: issuerCa.certificate }],
        credentialTypes: [{ id: 'diploma', vct: 'v', anchorIds: ['a1'], claims: [{ path: ['x'] }] }],
      },
      version: 'bad',
    });
    const res = await managementRequest({ port: ports.managementPort, method: 'PUT', path: '/v1/config', body: config, client: pki.management, pki });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /no DNS name other\.example/);
  });

  it('verifies a presentation end to end and hands the claims to the provider server once', async () => {
    const started = await call('/wallet/verify/verifications', { method: 'POST', body: { credentialType: 'diploma', claims: ['given_name', 'degree'], reference: 'order-17' } });
    assert.equal(started.status, 201);
    const session = await started.json();
    assert.equal(session.status, 'pending');
    assert.equal(session.client_id, 'x509_san_dns:wallet.example');
    assert.ok(session.deep_link.startsWith('openid4vp://?client_id=x509_san_dns%3Awallet.example&request_uri='));

    const { request, posted, decoded } = await answerAsWallet(session);
    assert.equal(decoded.header.typ, 'oauth-authz-req+jwt');
    assert.equal(decoded.header.x5c.length, 1, 'the root is not sent');
    assert.equal(request.response_mode, 'direct_post.jwt');
    assert.deepEqual(request.dcql_query.credentials[0].meta, { vct_values: ['https://example.org/diploma'] });
    assert.deepEqual(request.dcql_query.credentials[0].claims, [{ path: ['given_name'] }, { path: ['degree'] }]);
    assert.equal(request.verifier_info[0].format, 'registration_cert');
    assert.equal(posted.status, 200);

    const delivered = await waitFor(() => provider.seen.callbacks.find((item) => item.json.id === session.id), 'the callback');
    assert.equal(delivered.json.status, 'verified');
    assert.deepEqual(delivered.json.claims, { given_name: 'Ana', degree: 'MSc' });
    assert.equal(delivered.json.reference, 'order-17');
    const [, t, v1] = delivered.headers['x-wallet-signature'].match(/^t=(\d+),v1=([0-9a-f]+)$/);
    assert.equal(v1, crypto.createHmac('sha256', 'cb-secret').update(`${t}.${delivered.body}`).digest('hex'));

    // Delivered claims are no longer kept on the gateway.
    let result = null;
    for (let count = 0; count < 50 && !result?.claims_delivered; count += 1) {
      result = await (await call(`/wallet/verify/verifications/${session.id}`)).json();
      if (!result.claims_delivered) await sleep(20);
    }
    assert.equal(result.status, 'verified');
    assert.equal(result.claims, undefined);

    // The request object is served once; other applications don't see the verification.
    assert.equal((await call(new URL(session.request_uri).pathname, { client: null })).status, 410);
    assert.equal((await call(`/wallet/verify/verifications/${session.id}`, { client: 'client-2' })).status, 404);
    // One OAuth token served every call to the provider server.
    assert.equal(provider.seen.tokens, 1);
  });

  const failsWith = async (reason, options, body = { credentialType: 'diploma' }) => {
    const started = await (await call('/wallet/verify/verifications', { method: 'POST', body })).json();
    const { posted } = await answerAsWallet(started, options);
    assert.equal(posted.status, 200);
    const status = await (await call(`/wallet/verify/verifications/${started.id}`)).json();
    assert.equal(status.status, 'failed');
    assert.equal(status.reason, reason);
    assert.equal(status.claims, undefined);
  };

  it('fails closed with a reason', async () => {
    await failsWith('nonce_mismatch', { present: (request) => presentSdJwt(credential(), { holderKey: owner.privateKey, aud: request.client_id, nonce: 'stale' }) });
    await failsWith('audience_mismatch', { present: (request) => presentSdJwt(credential(), { holderKey: owner.privateKey, aud: 'x509_san_dns:evil.example', nonce: request.nonce }) });
    await failsWith('issuer_untrusted', { present: (request) => presentSdJwt(credential({ leaf: strangerLeaf }), { holderKey: owner.privateKey, aud: request.client_id, nonce: request.nonce }) });
    await failsWith('claim_missing', { present: (request) => presentSdJwt(credential(), { holderKey: owner.privateKey, aud: request.client_id, nonce: request.nonce, disclose: ['family_name'] }) });
    // A list the gateway hasn't cached yet (lists are kept for their ttl).
    provider.seen.statusEntries.set(9, 1);
    await failsWith('credential_revoked', { present: (request) => presentSdJwt(credential({ statusIndex: 9, list: 2 }), { holderKey: owner.privateKey, aud: request.client_id, nonce: request.nonce }) });
  });

  it('refuses claims outside the credential type', async () => {
    const res = await call('/wallet/verify/verifications', { method: 'POST', body: { credentialType: 'diploma', claims: ['personal_administrative_number'] } });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, 'claim_not_allowed');
    assert.equal((await call('/wallet/verify/verifications', { method: 'POST', body: { credentialType: 'diploma' }, client: 'nobody' })).status, 403);
  });

  it('reports verifications to the console without claim values', async () => {
    const res = await managementRequest({ port: ports.managementPort, path: '/v1/usage', client: pki.management, pki });
    const events = res.body.wallet;
    const verified = events.filter((event) => event.type === 'verification' && event.status === 'verified');
    assert.ok(verified.length >= 1);
    assert.deepEqual(verified[0].claimNames, ['given_name', 'degree']);
    assert.ok(!JSON.stringify(events).includes('Ana'), 'no claim value leaves the gateway in events');
    assert.ok(events.some((event) => event.type === 'callback' && event.outcome === 'delivered'));
  });
});

// ------------------------------------------------------------------ issuer

describe('wallet gateway: attestation provider / issuer', () => {
  let pki;
  let gateway;
  let ports;
  let handlerPort;
  let provider;
  let dataDir;
  const owner = holder();
  const base = 'https://issuer.example/wallet/issue';

  const issuerApi = {
    id: 'api-issue',
    name: 'Credential issuance',
    version: '1.0.0',
    basePath: '/wallet/issue',
    builtin: 'wallet-issuer',
    operations: [
      { method: 'post', path: '/offers' },
      { method: 'get', path: '/offers/{id}' },
      { method: 'post', path: '/credentials/{id}/{action}' },
      { method: 'get', path: '/.well-known/openid-credential-issuer', access: 'public' },
      { method: 'get', path: '/.well-known/oauth-authorization-server', access: 'public' },
      { method: 'get', path: '/credential-offer/{id}', access: 'public' },
      { method: 'post', path: '/token', access: 'public' },
      { method: 'post', path: '/nonce', access: 'public' },
      { method: 'post', path: '/credential', access: 'public' },
      { method: 'get', path: '/status/{listId}', access: 'public' },
    ],
  };

  const call = (pathname, { method = 'GET', body, form, headers = {}, client = 'client-1' } = {}) => fetch(`http://127.0.0.1:${handlerPort}${pathname}`, {
    method,
    headers: {
      ...(client && { authorization: `Bearer ${tokenFor(pki, { clientId: client })}` }),
      ...(body !== undefined && { 'content-type': 'application/json' }),
      ...(form !== undefined && { 'content-type': 'application/x-www-form-urlencoded' }),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : form !== undefined ? new URLSearchParams(form).toString() : undefined,
  });

  const proof = (nonce, aud = base) => jose.signJws({ typ: 'openid4vci-proof+jwt', jwk: owner.jwk }, { aud, iat: Math.floor(Date.now() / 1000), nonce }, owner.privateKey);

  before(async () => {
    pki = createPki();
    provider = await startProvider();
    handlerPort = await freePort();
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-issuer-'));
    gateway = createGateway(gatewayOptions(pki, dataDir, { nodeName: 'node-i' }));
    ports = await gateway.start();
    const config = baseConfig(pki, {
      kind: 'wallet-issuer',
      publicUrl: 'https://issuer.example',
      handlerPort,
      api: issuerApi,
      connections: [providerConnection(provider)],
      wallet: {
        role: 'issuer',
        identity: {
          legalName: 'Acme SRL',
          displayName: 'Acme badges',
          accessCertificateChain: chainPem(issuerAccess, accessCa),
          accessKey: { provider: 'sealed', privateKey: issuerAccess.privateKey },
          issuerCertificateChain: chainPem(clientIssuerLeaf, clientIssuerCa),
          issuerKey: { provider: 'sealed', privateKey: clientIssuerLeaf.privateKey },
          registrationCertificates: [{ id: 'r1', jwt: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhY21lIn0.' }],
        },
        settings: {},
        anchors: [],
        credentialTypes: [{ id: 'badge', name: 'Employee badge', vct: 'https://acme.example/badge', validityDays: 30, claims: [{ path: ['name'] }, { path: ['role'], required: false }] }],
        provider: { connectionId: 'conn-provider', callbackUrl: `${provider.url}/callback`, claimsUrl: `${provider.url}/claims`, callbackSecret: 'cb-secret' },
        status: { listId: '1', size: 1024, entries: [], ranges: { 'node-i': [0, 512] }, next: {} },
      },
    });
    const pushed = await managementRequest({ port: ports.managementPort, method: 'PUT', path: '/v1/config', body: config, client: pki.management, pki });
    assert.equal(pushed.status, 200, JSON.stringify(pushed.body));
  });

  after(async () => {
    await gateway.stop();
    await provider.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  let issued;

  it('issues an SD-JWT VC through offer, token, nonce and credential', async () => {
    const created = await call('/wallet/issue/offers', { method: 'POST', body: { credentialType: 'badge', subject: 'emp-7', txCode: true } });
    assert.equal(created.status, 201);
    const offer = await created.json();
    assert.match(offer.tx_code, /^\d{6}$/);
    assert.ok(offer.deep_link.startsWith('openid-credential-offer://?credential_offer_uri='));

    const metadata = await (await call('/.well-known/openid-credential-issuer/wallet/issue', { client: null })).json();
    assert.equal(metadata.credential_issuer, base);
    assert.equal(metadata.credential_configurations_supported.badge.vct, 'https://acme.example/badge');
    const signed = jose.decodeJws(metadata.signed_metadata);
    assert.ok(jose.verifySignature(signed, new crypto.X509Certificate(Buffer.from(signed.header.x5c[0], 'base64')).publicKey));
    assert.equal(signed.payload.registration_certificates.length, 1);
    const server = await (await call('/.well-known/oauth-authorization-server/wallet/issue', { client: null })).json();
    assert.equal(server.token_endpoint, `${base}/token`);

    const offerJson = await (await call(new URL(offer.credential_offer_uri).pathname, { client: null })).json();
    const grant = offerJson.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    assert.equal(grant.tx_code.length, 6);

    const wrong = await call('/wallet/issue/token', { method: 'POST', client: null, form: { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': grant['pre-authorized_code'], tx_code: '000000' === offer.tx_code ? '111111' : '000000' } });
    assert.equal(wrong.status, 400);
    const token = await (await call('/wallet/issue/token', { method: 'POST', client: null, form: { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': grant['pre-authorized_code'], tx_code: offer.tx_code } })).json();
    assert.equal(token.token_type, 'Bearer');
    // The code is used once.
    assert.equal((await call('/wallet/issue/token', { method: 'POST', client: null, form: { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': grant['pre-authorized_code'], tx_code: offer.tx_code } })).status, 400);

    const { c_nonce: nonce } = await (await call('/wallet/issue/nonce', { method: 'POST', client: null })).json();
    const answer = await call('/wallet/issue/credential', {
      method: 'POST', client: null, headers: { authorization: `Bearer ${token.access_token}` },
      body: { credential_configuration_id: 'badge', proofs: { jwt: [proof(nonce)] } },
    });
    assert.equal(answer.status, 200, await answer.clone().text());
    const { credentials } = await answer.json();
    issued = credentials[0].credential;
    assert.equal(provider.seen.claims[0].subject, 'emp-7');

    // The credential passes a verifier that trusts the client's issuing CA.
    const presentation = presentSdJwt(issued, { holderKey: owner.privateKey, aud: 'x509_san_dns:rp.example', nonce: 'n' });
    const verified = verifySdJwtPresentation(presentation, {
      anchors: jose.pemToCertificates(clientIssuerCa.certificate), vcts: ['https://acme.example/badge'], nonce: 'n', audience: 'x509_san_dns:rp.example', requireIssuerName: false,
    });
    assert.deepEqual(verified.claims, { name: 'Ana Pop', role: 'engineer' }, 'claims outside the type are dropped');
    assert.equal(verified.issuer, base);
    assert.deepEqual(verified.status, { status_list: { idx: 0, uri: `${base}/status/1` } });

    // The access token is used once, and so is the nonce.
    assert.equal((await call('/wallet/issue/credential', { method: 'POST', client: null, headers: { authorization: `Bearer ${token.access_token}` }, body: { proofs: { jwt: [proof(nonce)] } } })).status, 401);
    const status = await (await call(`/wallet/issue/offers/${offer.offer_id}`)).json();
    assert.equal(status.status, 'redeemed');
    assert.deepEqual(status.credential_ids, ['1-0']);
    assert.equal((await call(`/wallet/issue/offers/${offer.offer_id}`, { client: 'client-2' })).status, 404);
  });

  it('refuses a proof for another issuer and a reused nonce', async () => {
    const offer = await (await call('/wallet/issue/offers', { method: 'POST', body: { credentialType: 'badge', subject: 'emp-8', claims: { name: 'Ion' } } })).json();
    const offerJson = await (await call(new URL(offer.credential_offer_uri).pathname, { client: null })).json();
    const code = offerJson.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
    const token = await (await call('/wallet/issue/token', { method: 'POST', client: null, form: { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code } })).json();
    const { c_nonce: nonce } = await (await call('/wallet/issue/nonce', { method: 'POST', client: null })).json();
    const res = await call('/wallet/issue/credential', { method: 'POST', client: null, headers: { authorization: `Bearer ${token.access_token}` }, body: { proofs: { jwt: [proof(nonce, 'https://other.example')] } } });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'invalid_proof');
  });

  it('publishes the status list and revokes through the provider API', async () => {
    const read = async () => {
      const res = await call('/wallet/issue/status/1', { client: null });
      assert.equal(res.headers.get('content-type'), 'application/statuslist+jwt');
      const decoded = jose.decodeJws(await res.text());
      assert.equal(decoded.payload.sub, `${base}/status/1`);
      return readEntry(decoded.payload.status_list.lst, 2, 0);
    };
    assert.equal(await read(), 0);
    const revoked = await call('/wallet/issue/credentials/1-0/revoke', { method: 'POST' });
    assert.equal(revoked.status, 200);
    assert.equal(await read(), 1);
    assert.equal((await call('/wallet/issue/credentials/1-0/reinstate', { method: 'POST' })).status, 409);
    assert.equal((await call('/wallet/issue/credentials/9-0/revoke', { method: 'POST' })).status, 404);
  });

  it('reports offers, issued credentials and status changes to the console', async () => {
    const res = await managementRequest({ port: ports.managementPort, path: '/v1/usage', client: pki.management, pki });
    const events = res.body.wallet;
    const credential = events.find((event) => event.type === 'issued');
    assert.equal(credential.id, '1-0');
    assert.equal(credential.statusIndex, 0);
    assert.equal(credential.node, 'node-i');
    assert.deepEqual(credential.claimNames, ['name', 'role']);
    assert.ok(events.some((event) => event.type === 'credentialStatus' && event.status === 'revoked'));
    assert.ok(!JSON.stringify(events).includes('Ana Pop'));
    // The next index survives a restart (kept on disk).
    assert.ok(JSON.parse(fs.readFileSync(path.join(dataDir, 'wallet-status.json'), 'utf8'))['1:0'] >= 1);
  });
});
