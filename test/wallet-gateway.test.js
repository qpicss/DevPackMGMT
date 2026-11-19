// EU Wallet gateways in the console: kinds, the client's certificates and keys (sealed, never
// returned), credential types and trust anchors, the one-step setup, the schema 3 configuration
// (accepted by the gateway's own validation, secrets redacted in the preview), records reported
// by the nodes, revocation, and the OAuth client credentials connection type.
const helpers = require('./helpers');

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const forge = require('node-forge');
const { resetDatabase, createUser, api, models } = helpers;
const { Gateway, GatewayNode, Subscription, Api, Application, WalletVerification, WalletIssuedCredential, Connection } = models;
const { buildGatewayConfig, redactConfig } = require('../services/gatewayConfig');
const { recordWalletEvents } = require('../services/walletEvents');
const { gatewayIncludes } = require('../services/gatewayQueries');
const { compileConfig } = require('../gateway/src/runtime');

const keyPair = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const certificate = ({ commonName, issuer, ca = false, dns = [] }) => {
  const keys = keyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
  cert.serialNumber = `01${crypto.randomBytes(15).toString('hex')}`;
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000 * 90);
  const subject = [{ name: 'commonName', value: commonName }];
  cert.setSubject(subject);
  cert.setIssuer(issuer ? forge.pki.certificateFromPem(issuer.certificate).subject.attributes : subject);
  cert.setExtensions(ca
    ? [{ name: 'basicConstraints', cA: true, critical: true }, { name: 'keyUsage', keyCertSign: true, critical: true }]
    : [{ name: 'basicConstraints', cA: false }, ...(dns.length ? [{ name: 'subjectAltName', altNames: dns.map((value) => ({ type: 2, value })) }] : [])]);
  cert.sign(forge.pki.privateKeyFromPem(issuer ? issuer.privateKey : keys.privateKey), forge.md.sha256.create());
  return { certificate: forge.pki.certificateToPem(cert), privateKey: keys.privateKey };
};

const accessCa = certificate({ commonName: 'Access CA', ca: true });
const access = certificate({ commonName: 'Client RP', issuer: accessCa, dns: ['wallet.example'] });
const issuerCert = certificate({ commonName: 'Client issuer', issuer: accessCa, dns: ['wallet.example'] });
const pidCa = certificate({ commonName: 'PID provider CA', ca: true });
const fakeJwt = (payload) => `${Buffer.from('{"alg":"ES256","typ":"rc-wrp+jwt"}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.c2ln`;

const load = (id) => Gateway.findByPk(id, { include: gatewayIncludes });

describe('EU Wallet gateways in the console', () => {
  let admin;

  beforeEach(async () => {
    await resetDatabase();
    admin = await createUser();
  });

  const createWalletGateway = async (kind = 'wallet-verifier') => {
    const res = await api('post', '/api/org/gateways', admin).send({ name: kind === 'wallet-verifier' ? 'RP gateway' : 'Issuer gateway', publicUrl: 'https://wallet.example', kind });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    return res.body.gateway;
  };

  const configure = async (gatewayId, { issuer = false } = {}) => {
    const url = `/api/org/gateways/${gatewayId}/wallet`;
    const identity = await api('put', `${url}/identity`, admin).send({
      legalName: 'Acme SRL',
      accessCertificatePem: access.certificate + accessCa.certificate,
      accessKeyPem: access.privateKey,
      registrationCertificate: fakeJwt({ sub: 'Acme SRL', exp: Math.floor(Date.now() / 1000) + 86400 }),
      ...(issuer && { issuerCertificatePem: issuerCert.certificate, issuerKeyPem: issuerCert.privateKey }),
    });
    assert.equal(identity.status, 200, JSON.stringify(identity.body));
    const anchor = await api('post', `${url}/anchors`, admin).send({ name: 'PID providers', entitlement: 'PID', certificatesPem: pidCa.certificate });
    assert.equal(anchor.status, 201, JSON.stringify(anchor.body));
    const type = await api('post', `${url}/types`, admin).send({
      key: 'pid', name: 'PID', vct: 'urn:eudi:pid:1', anchorIds: [anchor.body.anchor.id],
      claims: ['given_name', { path: 'address.locality', required: false }],
    });
    assert.equal(type.status, 201, JSON.stringify(type.body));
    const settings = await api('put', `${url}/settings`, admin).send({ provider: { callbackUrl: 'https://provider.example/wallet/events', ...(issuer && { claimsUrl: 'https://provider.example/wallet/claims' }) } });
    assert.equal(settings.status, 200, JSON.stringify(settings.body));
    const secret = await api('post', `${url}/callback-secret`, admin);
    assert.match(secret.body.callbackSecret, /^[A-Za-z0-9_-]{40,}$/);
    return { anchorId: anchor.body.anchor.id, typeId: type.body.type.id, callbackSecret: secret.body.callbackSecret };
  };

  it('creates gateways of a fixed kind', async () => {
    const plain = await api('post', '/api/org/gateways', admin).send({ name: 'APIs', publicUrl: 'https://api.example.com' });
    assert.equal(plain.body.gateway.kind, 'api');
    assert.equal((await api('post', '/api/org/gateways', admin).send({ name: 'X', publicUrl: 'https://x.example', kind: 'psd' })).status, 400);
    const gateway = await createWalletGateway();
    assert.equal(gateway.kind, 'wallet-verifier');
    assert.equal((await api('put', `/api/org/gateways/${gateway.id}`, admin).send({ kind: 'api' })).status, 409);
    // An API gateway has no wallet settings.
    assert.equal((await api('get', `/api/org/gateways/${plain.body.gateway.id}/wallet`, admin)).status, 409);
  });

  it('stores the certificates, keeps the keys sealed and lists what is missing', async () => {
    const gateway = await createWalletGateway();
    const url = `/api/org/gateways/${gateway.id}/wallet`;
    const empty = await api('get', url, admin);
    assert.ok(empty.body.wallet.problems.some((problem) => /access certificate/.test(problem)));

    const other = certificate({ commonName: 'Other' });
    const mismatch = await api('put', `${url}/identity`, admin).send({ accessCertificatePem: access.certificate, accessKeyPem: other.privateKey });
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.body.error, /does not belong/);

    await configure(gateway.id);
    const res = await api('get', url, admin);
    const text = JSON.stringify(res.body);
    assert.ok(!text.includes('PRIVATE KEY') && !text.includes('callbackSecret"'), 'no key or secret is returned');
    assert.equal(res.body.wallet.identity.hasAccessKey, true);
    assert.match(res.body.wallet.identity.accessCertificate.subjectAltName, /wallet\.example/);
    assert.equal(res.body.wallet.identity.registrationCertificates[0].subject, 'Acme SRL');
    assert.deepEqual(res.body.wallet.types[0].claims, [{ path: ['given_name'], label: null, required: true }, { path: ['address', 'locality'], label: null, required: false }]);
    const stored = await Gateway.findByPk(gateway.id);
    assert.ok(!String(stored.walletSecretsSealed).includes('PRIVATE KEY'));
    // An anchor still used by a type stays.
    assert.equal((await api('delete', `${url}/anchors/${res.body.wallet.anchors[0].id}`, admin)).status, 409);
  });

  it('sets up the built-in API, product and provider server application once', async () => {
    const gateway = await createWalletGateway();
    const url = `/api/org/gateways/${gateway.id}/wallet`;
    const first = await api('post', `${url}/setup`, admin);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.api.basePath, '/wallet/verify');
    assert.ok(first.body.application.clientSecret);
    assert.equal(first.body.attached, false, 'a gateway that never ran is not attached');
    const second = await api('post', `${url}/setup`, admin);
    assert.equal(second.body.api.id, first.body.api.id);
    assert.equal(second.body.application.clientSecret, undefined, 'the secret is shown once');
    const subscription = await Subscription.findOne({ where: { productId: first.body.product.id } });
    assert.equal(subscription.status, 'approved');
    const created = await Api.findByPk(first.body.api.id);
    assert.equal(created.spec.info['x-wallet-builtin'], 'wallet-verifier');
    const application = await Application.findByPk(first.body.application.id);
    assert.equal(application.clientSecret, Application.hashSecret(first.body.application.clientSecret));
  });

  it('builds a schema 3 configuration the gateway accepts, with secrets redacted in the preview', async () => {
    const gateway = await createWalletGateway();
    const { callbackSecret } = await configure(gateway.id);
    const setup = await api('post', `/api/org/gateways/${gateway.id}/wallet/setup`, admin);
    await Gateway.update({ catalogId: setup.body.catalog.id }, { where: { id: gateway.id } });

    const { config, problems } = await buildGatewayConfig(await load(gateway.id));
    assert.deepEqual(problems.filter((problem) => !/connection handler/.test(problem)), []);
    assert.equal(config.schema, 3);
    assert.equal(config.gateway.kind, 'wallet-verifier');
    assert.equal(config.apis[0].builtin, 'wallet-verifier');
    assert.ok(config.apis[0].operations.some((operation) => operation.path === '/response/{id}' && operation.access === 'public'));
    assert.equal(config.wallet.provider.callbackSecret, callbackSecret);
    assert.match(config.wallet.identity.accessKey.privateKey, /PRIVATE KEY/);

    // The gateway's own validation compiles it.
    const compiled = compileConfig(config, { gatewayId: gateway.id });
    assert.equal(compiled.wallet.identity.clientId, 'x509_san_dns:wallet.example');
    assert.equal(compiled.wallet.types.get('pid').anchors.length, 1);

    const preview = JSON.stringify(redactConfig(config));
    assert.ok(!preview.includes('PRIVATE KEY'));
    assert.ok(!preview.includes(callbackSecret));
  });

  it('leaves API gateways at schema 2 without wallet fields', async () => {
    const res = await api('post', '/api/org/gateways', admin).send({ name: 'APIs', publicUrl: 'https://api.example.com' });
    const { config } = await buildGatewayConfig(await load(res.body.gateway.id));
    assert.equal(config.schema, 2);
    assert.equal(config.gateway.kind, undefined);
    assert.equal(config.wallet, undefined);
  });

  it('flags a certificate that does not name the public host', async () => {
    const res = await api('post', '/api/org/gateways', admin).send({ name: 'Elsewhere', publicUrl: 'https://other.example', kind: 'wallet-verifier' });
    await configure(res.body.gateway.id);
    const { problems } = await buildGatewayConfig(await load(res.body.gateway.id));
    assert.ok(problems.some((problem) => /no DNS name other\.example/.test(problem)));
  });

  it('renders the Wallet page for both roles', async () => {
    for (const kind of ['wallet-verifier', 'wallet-issuer']) {
      const gateway = await createWalletGateway(kind);
      await configure(gateway.id, { issuer: kind === 'wallet-issuer' });
      const page = await helpers.browser('get', `/developer/gateways/${gateway.id}/wallet`, admin);
      assert.equal(page.status, 200, page.text.slice(0, 500));
      assert.match(page.text, /Credential types/);
      assert.match(page.text, kind === 'wallet-issuer' ? /Issued credentials/ : /Verifications/);
      assert.ok(!page.text.includes(access.privateKey.split(/\r?\n/)[1]), 'no key material on the page');
      // Setup is not run yet, so the five-step checklist shows, with the diploma preset and tutorial.
      assert.match(page.text, /Up and running in five steps/);
      assert.match(page.text, /data-diploma-preset/);
      assert.match(page.text, kind === 'wallet-issuer' ? /tutorials\/10-issue-diplomas/ : /tutorials\/09-verify-a-diploma/);
      const detail = await helpers.browser('get', `/developer/gateways/${gateway.id}`, admin);
      assert.equal(detail.status, 200);
      assert.match(detail.text, /data-wallet-link/);
    }
    const list = await helpers.browser('get', '/developer/gateways', admin);
    assert.match(list.text, /EU Wallet: issuer/);
  });

  it('keeps wallet settings to their organization', async () => {
    const gateway = await createWalletGateway();
    const stranger = await createUser();
    assert.equal((await api('get', `/api/org/gateways/${gateway.id}/wallet`, stranger)).status, 404);
    assert.equal((await api('post', `/api/org/gateways/${gateway.id}/wallet/setup`, stranger)).status, 404);
  });

  it('records verifications reported by the nodes, without claim values', async () => {
    const gateway = await createWalletGateway();
    const stored = await recordWalletEvents(await load(gateway.id), [
      { type: 'verification', id: 'sess-1', clientId: 'c1', credentialType: 'pid', status: 'pending', createdAt: new Date().toISOString() },
      { type: 'verification', id: 'sess-1', clientId: 'c1', credentialType: 'pid', status: 'verified', issuer: 'https://pid.example', claimNames: ['given_name'], completedAt: new Date().toISOString() },
      { type: 'callback', event: 'verification.completed', id: 'sess-1', outcome: 'delivered' },
      // Issuer events don't belong on a verifier gateway.
      { type: 'issued', id: '1-0', statusIndex: 0 },
    ]);
    assert.equal(stored, 3);
    const records = await api('get', `/api/org/gateways/${gateway.id}/wallet/records`, admin);
    assert.equal(records.body.verifications.length, 1);
    assert.equal(records.body.verifications[0].status, 'verified');
    assert.equal(records.body.verifications[0].callback, 'delivered');
    assert.deepEqual(records.body.verifications[0].claimNames, ['given_name']);
    assert.equal(await WalletIssuedCredential.count(), 0);
    // A final state is never undone by a late event.
    await recordWalletEvents(await load(gateway.id), [{ type: 'verification', id: 'sess-1', status: 'pending' }]);
    assert.equal((await WalletVerification.findOne()).status, 'verified');
  });

  it('issues status list blocks per node and publishes revocations in the configuration', async () => {
    const gateway = await createWalletGateway('wallet-issuer');
    await configure(gateway.id, { issuer: true });
    await GatewayNode.create({ gatewayId: gateway.id, name: 'node-a', mode: 'pull' });
    await GatewayNode.create({ gatewayId: gateway.id, name: 'node-b', mode: 'pull' });
    await recordWalletEvents(await load(gateway.id), [
      { type: 'issued', id: '1-0', statusIndex: 0, listId: '1', node: 'node-a', credentialType: 'pid', subject: 'emp-1', claimNames: ['given_name'] },
      { type: 'issued', id: '1-16384', statusIndex: 16384, listId: '1', node: 'node-b', credentialType: 'pid', subject: 'emp-2' },
      { type: 'credentialStatus', id: '1-16384', status: 'suspended' },
    ]);
    const url = `/api/org/gateways/${gateway.id}/wallet`;
    const revoke = await api('post', `${url}/credentials/1-0/revoke`, admin);
    assert.equal(revoke.status, 200);
    assert.equal((await api('post', `${url}/credentials/1-0/reinstate`, admin)).status, 409);
    assert.equal((await api('post', `${url}/credentials/9-9/revoke`, admin)).status, 404);

    const { config } = await buildGatewayConfig(await load(gateway.id));
    assert.deepEqual(config.wallet.status.ranges, { 'node-a': [0, 16384], 'node-b': [16384, 32768] });
    assert.deepEqual(config.wallet.status.next, { 'node-a': 1, 'node-b': 16385 });
    assert.deepEqual(config.wallet.status.entries, [[0, 1], [16384, 2]]);
    assert.match(config.wallet.identity.issuerKey.privateKey, /PRIVATE KEY/);
    // Blocks never move: a third node gets the next free one.
    await GatewayNode.create({ gatewayId: gateway.id, name: 'node-0', mode: 'pull' });
    const after = await buildGatewayConfig(await load(gateway.id));
    assert.deepEqual(after.config.wallet.status.ranges['node-a'], [0, 16384]);
    assert.deepEqual(after.config.wallet.status.ranges['node-0'], [32768, 49152]);
    assert.ok(!JSON.stringify(redactConfig(after.config)).includes('PRIVATE KEY'));
  });

  it('refuses software keys for qualified and public-body issuers', async () => {
    const gateway = await createWalletGateway('wallet-issuer');
    await configure(gateway.id, { issuer: true });
    await api('put', `/api/org/gateways/${gateway.id}/wallet/identity`, admin).send({ legalCategory: 'QEAA' });
    const { problems } = await buildGatewayConfig(await load(gateway.id));
    assert.ok(problems.some((problem) => /QEAA issuers sign with a key in their HSM/.test(problem)));
  });

  it('stores OAuth client credentials on a connection without returning the secret', async () => {
    const res = await api('post', '/api/org/connections', admin).send({
      name: 'Provider server',
      auth: { type: 'oauth2', tokenUrl: 'https://auth.provider.example/oauth/token', clientId: 'gateway', secret: 'top-secret', scope: 'wallet' },
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.equal(res.body.connection.auth.tokenUrl, 'https://auth.provider.example/oauth/token');
    assert.equal(res.body.connection.auth.clientAuthMethod, 'client_secret_basic');
    assert.ok(!JSON.stringify(res.body).includes('top-secret'));
    assert.equal((await api('post', '/api/org/connections', admin).send({ name: 'Bad', auth: { type: 'oauth2', tokenUrl: 'http://auth.example/token', clientId: 'x', secret: 'y' } })).status, 400);

    // Used as the provider server's connection, it reaches the gateway with its secret (hidden in the preview).
    const gateway = await createWalletGateway();
    await configure(gateway.id);
    const connection = await Connection.findOne({ where: { name: 'Provider server' } });
    await api('put', `/api/org/gateways/${gateway.id}/wallet/settings`, admin).send({ provider: { connectionId: connection.id, callbackUrl: 'https://provider.example/events' } });
    const { config } = await buildGatewayConfig(await load(gateway.id));
    const entry = config.connections.find((item) => item.id === connection.id);
    assert.equal(entry.auth.type, 'oauth2');
    assert.equal(entry.auth.secret, 'top-secret');
    assert.ok(!JSON.stringify(redactConfig(config)).includes('top-secret'));
    compileConfig(config, { gatewayId: gateway.id });
  });
});
