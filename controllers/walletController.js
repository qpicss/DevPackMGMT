// EU Wallet gateways (kind wallet-verifier or wallet-issuer): the client's identity (access,
// registration and issuer certificates with their keys), settings and provider server, trust
// anchors, credential types, the one-step setup of the built-in API (catalog, API, product and the
// provider server's application) and the records (verifications, issued credentials).
// Private keys and the callback secret are sealed (utils/secretBox.js) and never returned.
const crypto = require('crypto');
const sequelize = require('../config/database');
const {
  Gateway, Catalog, Api, ApiProduct, ProductApi, Application, Subscription, Policy, Connection,
  WalletTrustAnchor, WalletCredentialType, WalletVerification, WalletIssuedCredential,
} = require('../models');
const { sendServerError } = require('../utils/http');
const { seal } = require('../utils/secretBox');
const { gatewayIncludes } = require('../services/gatewayQueries');
const { buildGatewayConfig } = require('../services/gatewayConfig');
const { isGatewayRunning } = require('../services/gatewayPush');
const { scheduleAutoPush } = require('../services/autoPush');
const { defaultFlow } = require('../gateway/src/flow');
const { BUILTINS, KIND_BUILTIN, builtinSpec, builtinOf } = require('../utils/walletBuiltins');
const {
  ROLE, ENTITLEMENTS, LEGAL_CATEGORIES, DEFAULT_SETTINGS, isWallet, walletSettingsOf, walletSecretsOf,
  describeCertificate, certificatesOf, registrationPayload,
} = require('../services/walletConfig');

const KEY = /^[A-Za-z0-9_-]{1,64}$/;
const CLIENT_ID_SCHEMES = ['x509_san_dns', 'x509_hash'];
const RESPONSE_MODES = ['direct_post.jwt', 'direct_post'];
const MAX_PEM = 64 * 1024;
const MAX_CLAIMS = 100;

class InputError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const findWalletGateway = async (req) => {
  const gateway = await Gateway.findOne({ where: { id: req.params.id, organizationId: req.user.organizationId }, include: gatewayIncludes });
  if (!gateway) throw new InputError('Gateway not found', 404);
  if (!isWallet(gateway)) throw new InputError('This is an API gateway. Wallet settings exist only on EU Wallet gateways.', 409);
  return gateway;
};

const handle = (label, fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (error) {
    if (error instanceof InputError) return res.status(error.status).json({ error: error.message });
    sendServerError(res, error, label);
  }
};

const text = (value, label, { max = 255, required = false } = {}) => {
  const result = typeof value === 'string' ? value.trim() : '';
  if (required && !result) throw new InputError(`${label} is required`);
  if (result.length > max) throw new InputError(`${label} is longer than ${max} characters`);
  return result;
};

const optionalUrl = (value, label) => {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new InputError(`${label} must be an http(s) address`);
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new InputError(`${label} must be an http(s) address`);
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(url.hostname)) throw new InputError(`${label} must use https`);
  return url.href;
};

// PEM certificates (a chain, leaf first). Returns the normalized PEM.
const certificateChain = (value, label) => {
  const pem = typeof value === 'string' ? value.trim() : '';
  if (pem.length > MAX_PEM) throw new InputError(`${label} is too large`);
  const blocks = certificatesOf(pem);
  if (!blocks.length) throw new InputError(`${label}: paste PEM certificates (-----BEGIN CERTIFICATE-----)`);
  try {
    blocks.forEach((block) => new crypto.X509Certificate(block));
  } catch {
    throw new InputError(`${label}: a certificate cannot be read`);
  }
  return `${blocks.join('\n')}\n`;
};

// A PEM private key that belongs to the first certificate of `chainPem`.
const privateKeyFor = (value, chainPem, label) => {
  const pem = typeof value === 'string' ? value.trim() : '';
  if (pem.length > MAX_PEM) throw new InputError(`${label} is too large`);
  let key;
  try {
    key = crypto.createPrivateKey(pem);
  } catch {
    throw new InputError(`${label}: paste an unencrypted PEM private key`);
  }
  if (!['ec', 'rsa', 'rsa-pss', 'ed25519'].includes(key.asymmetricKeyType)) throw new InputError(`${label}: use an EC (P-256/P-384), RSA or Ed25519 key`);
  const leaf = new crypto.X509Certificate(certificatesOf(chainPem)[0]);
  if (!leaf.checkPrivateKey(key)) throw new InputError(`${label} does not belong to the certificate`);
  return key.export({ type: 'pkcs8', format: 'pem' });
};

const serializeAnchor = (anchor) => ({
  id: anchor.id,
  name: anchor.name,
  entitlement: anchor.entitlement,
  certificates: certificatesOf(anchor.certificatesPem).map((pem) => describeCertificate(pem)),
});

const serializeType = (type) => ({
  id: type.id,
  key: type.key,
  name: type.name,
  vct: type.vct,
  claims: type.claims,
  anchorIds: type.anchorIds,
  display: type.display,
  validityDays: type.validityDays,
  requireIssuerName: type.requireIssuerName,
});

const serializeRegistration = (item) => {
  const payload = registrationPayload(item.jwt);
  return {
    id: item.id,
    addedAt: item.addedAt || null,
    subject: payload ? String(payload.sub || payload.name || payload.tradeName || '').slice(0, 200) || null : null,
    expiresAt: payload?.exp ? new Date(payload.exp * 1000).toISOString() : null,
    readable: Boolean(payload),
  };
};

// Everything the Wallet page and API show. Secrets only as "is set".
const describeWallet = async (gateway) => {
  const settings = walletSettingsOf(gateway);
  const secrets = walletSecretsOf(gateway);
  const [anchors, types, connections, { problems, problemDetails }] = await Promise.all([
    WalletTrustAnchor.findAll({ where: { gatewayId: gateway.id }, order: [['name', 'ASC']] }),
    WalletCredentialType.findAll({ where: { gatewayId: gateway.id }, order: [['key', 'ASC']] }),
    Connection.findAll({ where: { organizationId: gateway.organizationId }, attributes: ['id', 'name'], order: [['name', 'ASC']] }),
    buildGatewayConfig(gateway),
  ]);
  return {
    gateway: { id: gateway.id, name: gateway.name, kind: gateway.kind, publicUrl: gateway.publicUrl, catalog: gateway.catalog ? { id: gateway.catalog.id, name: gateway.catalog.name } : null },
    role: ROLE[gateway.kind],
    identity: {
      legalName: settings.legalName,
      displayName: settings.displayName,
      legalCategory: settings.legalCategory,
      accessCertificate: describeCertificate(settings.accessCertificatePem),
      hasAccessKey: Boolean(secrets.accessKeyPem),
      issuerCertificate: describeCertificate(settings.issuerCertificatePem),
      hasIssuerKey: Boolean(secrets.issuerKeyPem),
      registrationCertificates: settings.registrationCertificates.map(serializeRegistration),
    },
    settings: settings.settings,
    provider: { ...settings.provider, hasCallbackSecret: Boolean(secrets.callbackSecret) },
    walletProviderAnchorIds: settings.walletProviderAnchorIds,
    statusList: { listId: settings.statusList.listId, size: settings.statusList.size },
    anchors: anchors.map(serializeAnchor),
    types: types.map(serializeType),
    connections: connections.map((connection) => ({ id: connection.id, name: connection.name })),
    builtin: BUILTINS[KIND_BUILTIN[gateway.kind]],
    // Set up has created the built-in API, product and provider server application.
    setupDone: Boolean(gateway.walletSettings?.setupCatalogId),
    problems,
    problemDetails,
    options: { entitlements: ENTITLEMENTS, legalCategories: LEGAL_CATEGORIES, clientIdSchemes: CLIENT_ID_SCHEMES, responseModes: RESPONSE_MODES },
  };
};

const saveSettings = (gateway, changes, secretChanges) => {
  const settings = { ...(gateway.walletSettings || {}), ...changes };
  const fields = { walletSettings: settings };
  if (secretChanges) fields.walletSecretsSealed = seal(JSON.stringify({ ...walletSecretsOf(gateway), ...secretChanges }));
  return gateway.update(fields);
};

const changed = (gateway) => scheduleAutoPush(gateway.organizationId);

// ------------------------------------------------------------------ read

const getWallet = handle('Failed to load the wallet settings', async (req, res) => {
  const gateway = await findWalletGateway(req);
  res.json({ wallet: await describeWallet(gateway) });
});

// ------------------------------------------------------------------ identity and settings

const updateIdentity = handle('Failed to save the certificates', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const body = req.body || {};
  const current = walletSettingsOf(gateway);
  const changes = {};
  const secretChanges = {};
  if (body.legalName !== undefined) changes.legalName = text(body.legalName, 'Legal name');
  if (body.displayName !== undefined) changes.displayName = text(body.displayName, 'Display name');
  if (body.legalCategory !== undefined) {
    if (!LEGAL_CATEGORIES.includes(body.legalCategory)) throw new InputError(`Legal category must be one of ${LEGAL_CATEGORIES.join(', ')}`);
    changes.legalCategory = body.legalCategory;
  }
  const hasText = (value) => typeof value === 'string' && value.trim();
  if (hasText(body.accessCertificatePem) || hasText(body.accessKeyPem)) {
    const chain = certificateChain(body.accessCertificatePem || current.accessCertificatePem, 'Access certificate');
    if (!hasText(body.accessKeyPem)) throw new InputError('Paste the private key of the access certificate as well');
    secretChanges.accessKeyPem = privateKeyFor(body.accessKeyPem, chain, 'The access key');
    changes.accessCertificatePem = chain;
  }
  if (hasText(body.issuerCertificatePem) || hasText(body.issuerKeyPem)) {
    if (ROLE[gateway.kind] !== 'issuer') throw new InputError('Only issuer gateways have an issuer certificate');
    const chain = certificateChain(body.issuerCertificatePem || current.issuerCertificatePem, 'Issuer certificate');
    if (!hasText(body.issuerKeyPem)) throw new InputError('Paste the private key of the issuer certificate as well');
    secretChanges.issuerKeyPem = privateKeyFor(body.issuerKeyPem, chain, 'The issuer key');
    changes.issuerCertificatePem = chain;
  }
  if (hasText(body.registrationCertificate)) {
    const jwt = body.registrationCertificate.trim();
    if (jwt.length > MAX_PEM || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(jwt)) throw new InputError('The registration certificate must be a JWT (three dot-separated parts)');
    if (!registrationPayload(jwt)) throw new InputError('The registration certificate cannot be read');
    if (current.registrationCertificates.length >= 20) throw new InputError('At most 20 registration certificates');
    changes.registrationCertificates = [...current.registrationCertificates, { id: crypto.randomUUID(), jwt, addedAt: new Date().toISOString() }];
  }
  await saveSettings(gateway, changes, Object.keys(secretChanges).length ? secretChanges : null);
  changed(gateway);
  res.json({ wallet: await describeWallet(gateway) });
});

const removeRegistration = handle('Failed to remove the registration certificate', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const current = walletSettingsOf(gateway);
  const remaining = current.registrationCertificates.filter((item) => item.id !== req.params.registrationId);
  if (remaining.length === current.registrationCertificates.length) throw new InputError('Registration certificate not found', 404);
  await saveSettings(gateway, { registrationCertificates: remaining });
  changed(gateway);
  res.json({ message: 'Registration certificate removed' });
});

const whole = (value, fallback, min, max, label) => {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new InputError(`${label} must be a whole number from ${min} to ${max}`);
  return number;
};

const updateSettings = handle('Failed to save the wallet settings', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const body = req.body || {};
  const current = walletSettingsOf(gateway);
  const changes = {};
  if (body.settings !== undefined) {
    const raw = body.settings || {};
    const settings = { ...current.settings };
    if (raw.clientIdScheme !== undefined) {
      if (!CLIENT_ID_SCHEMES.includes(raw.clientIdScheme)) throw new InputError('Client ID must be x509_san_dns or x509_hash');
      settings.clientIdScheme = raw.clientIdScheme;
    }
    if (raw.responseMode !== undefined) {
      if (!RESPONSE_MODES.includes(raw.responseMode)) throw new InputError('Response mode must be direct_post.jwt or direct_post');
      settings.responseMode = raw.responseMode;
    }
    settings.sessionSeconds = whole(raw.sessionSeconds, settings.sessionSeconds, 30, 3600, 'The session time');
    settings.resultRetentionHours = whole(raw.resultRetentionHours, settings.resultRetentionHours, 1, 168, 'The retention');
    settings.offerTtlSeconds = whole(raw.offerTtlSeconds, settings.offerTtlSeconds, 60, 30 * 86400, 'The offer lifetime');
    settings.batchSize = whole(raw.batchSize, settings.batchSize, 1, 50, 'The batch size');
    if (raw.requireWalletAttestation !== undefined) settings.requireWalletAttestation = raw.requireWalletAttestation === true || raw.requireWalletAttestation === 'on';
    if (raw.verifierInfoFormat !== undefined) settings.verifierInfoFormat = text(raw.verifierInfoFormat, 'The verifier_info format', { max: 100 }) || DEFAULT_SETTINGS.verifierInfoFormat;
    changes.settings = settings;
  }
  if (body.provider !== undefined) {
    const raw = body.provider || {};
    let connectionId = null;
    if (raw.connectionId) {
      const connection = await Connection.findOne({ where: { id: raw.connectionId, organizationId: req.user.organizationId } });
      if (!connection) throw new InputError("Choose one of your organization's connections");
      connectionId = connection.id;
    }
    changes.provider = {
      connectionId,
      callbackUrl: optionalUrl(raw.callbackUrl, 'The callback URL'),
      claimsUrl: ROLE[gateway.kind] === 'issuer' ? optionalUrl(raw.claimsUrl, 'The claims URL') : null,
    };
  }
  if (body.walletProviderAnchorIds !== undefined) {
    const ids = Array.isArray(body.walletProviderAnchorIds) ? body.walletProviderAnchorIds.map(String) : [];
    const found = await WalletTrustAnchor.count({ where: { id: ids, gatewayId: gateway.id } });
    if (found !== new Set(ids).size) throw new InputError('Choose trust anchors of this gateway');
    changes.walletProviderAnchorIds = [...new Set(ids)];
  }
  await saveSettings(gateway, changes);
  changed(gateway);
  res.json({ wallet: await describeWallet(gateway) });
});

// A new callback secret, shown once; the provider server checks X-Wallet-Signature with it.
const rotateCallbackSecret = handle('Failed to create the callback secret', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const secret = crypto.randomBytes(32).toString('base64url');
  await saveSettings(gateway, {}, { callbackSecret: secret });
  changed(gateway);
  res.json({ callbackSecret: secret });
});

// ------------------------------------------------------------------ trust anchors

const createAnchor = handle('Failed to add the trust anchor', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const body = req.body || {};
  if (!ENTITLEMENTS.includes(body.entitlement)) throw new InputError(`Entitlement must be one of ${ENTITLEMENTS.join(', ')}`);
  const anchor = await WalletTrustAnchor.create({
    organizationId: gateway.organizationId,
    gatewayId: gateway.id,
    name: text(body.name, 'Name', { required: true }),
    entitlement: body.entitlement,
    certificatesPem: certificateChain(body.certificatesPem, 'Trust anchor'),
  });
  changed(gateway);
  res.status(201).json({ anchor: serializeAnchor(anchor) });
});

const deleteAnchor = handle('Failed to remove the trust anchor', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const anchor = await WalletTrustAnchor.findOne({ where: { id: req.params.anchorId, gatewayId: gateway.id } });
  if (!anchor) throw new InputError('Trust anchor not found', 404);
  const types = await WalletCredentialType.findAll({ where: { gatewayId: gateway.id } });
  const using = types.filter((type) => type.anchorIds.includes(anchor.id)).map((type) => type.name);
  if (using.length) throw new InputError(`Credential types still use this anchor: ${using.join(', ')}`, 409);
  if (walletSettingsOf(gateway).walletProviderAnchorIds.includes(anchor.id)) throw new InputError('This anchor is chosen for wallet attestations. Remove it there first.', 409);
  await anchor.destroy();
  changed(gateway);
  res.json({ message: 'Trust anchor removed' });
});

// ------------------------------------------------------------------ credential types

const PATH_PART = /^[A-Za-z0-9_.$#@-]{1,100}$/;
const parseClaims = (value) => {
  if (!Array.isArray(value) || !value.length || value.length > MAX_CLAIMS) throw new InputError(`List 1 to ${MAX_CLAIMS} claims`);
  const seen = new Set();
  return value.map((item) => {
    const raw = typeof item === 'string' ? { path: item } : item || {};
    const path = Array.isArray(raw.path) ? raw.path : String(raw.path || '').split('.').map((part) => part.trim()).filter(Boolean);
    if (!path.length || path.length > 10 || !path.every((part) => (typeof part === 'string' && PATH_PART.test(part)) || part === null || (Number.isInteger(part) && part >= 0))) {
      throw new InputError(`"${String(raw.path).slice(0, 80)}" is not a claim path; use names such as family_name or address.locality`);
    }
    const key = JSON.stringify(path);
    if (seen.has(key)) throw new InputError(`The claim ${path.join('.')} is listed twice`);
    seen.add(key);
    return { path, label: typeof raw.label === 'string' && raw.label.trim() ? raw.label.trim().slice(0, 100) : null, required: raw.required !== false };
  });
};

const typeFields = async (gateway, body, current = null) => {
  const fields = {};
  if (!current || body.key !== undefined) {
    const key = text(body.key, 'Identifier', { required: true, max: 64 });
    if (!KEY.test(key)) throw new InputError('The identifier may use letters, digits, - and _ (e.g. diploma)');
    const clash = await WalletCredentialType.findOne({ where: { gatewayId: gateway.id, key } });
    if (clash && clash.id !== current?.id) throw new InputError(`A credential type ${key} exists already`, 409);
    fields.key = key;
  }
  if (!current || body.name !== undefined) fields.name = text(body.name, 'Name', { required: true });
  if (!current || body.vct !== undefined) fields.vct = text(body.vct, 'The vct (credential type identifier)', { required: true, max: 500 });
  if (!current || body.claims !== undefined) fields.claims = parseClaims(body.claims);
  if (body.anchorIds !== undefined) {
    const ids = [...new Set((Array.isArray(body.anchorIds) ? body.anchorIds : []).map(String))];
    const found = await WalletTrustAnchor.count({ where: { id: ids, gatewayId: gateway.id } });
    if (found !== ids.length) throw new InputError('Choose trust anchors of this gateway');
    fields.anchorIds = ids;
  }
  if (body.validityDays !== undefined) fields.validityDays = whole(body.validityDays, 365, 1, 3650, 'The validity');
  if (body.requireIssuerName !== undefined) fields.requireIssuerName = body.requireIssuerName !== false && body.requireIssuerName !== 'false';
  if (body.display !== undefined) {
    const display = body.display || {};
    const name = typeof display.name === 'string' ? display.name.trim().slice(0, 100) : '';
    fields.display = name ? {
      name,
      locale: 'en',
      ...(typeof display.description === 'string' && display.description.trim() && { description: display.description.trim().slice(0, 300) }),
      ...(/^#[0-9A-Fa-f]{6}$/.test(display.backgroundColor || '') && { background_color: display.backgroundColor }),
      ...(/^#[0-9A-Fa-f]{6}$/.test(display.textColor || '') && { text_color: display.textColor }),
    } : null;
  }
  return fields;
};

const createType = handle('Failed to add the credential type', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const fields = await typeFields(gateway, req.body || {});
  const type = await WalletCredentialType.create({ ...fields, organizationId: gateway.organizationId, gatewayId: gateway.id });
  changed(gateway);
  res.status(201).json({ type: serializeType(type) });
});

const updateType = handle('Failed to save the credential type', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const type = await WalletCredentialType.findOne({ where: { id: req.params.typeId, gatewayId: gateway.id } });
  if (!type) throw new InputError('Credential type not found', 404);
  await type.update(await typeFields(gateway, req.body || {}, type));
  changed(gateway);
  res.json({ type: serializeType(type) });
});

const deleteType = handle('Failed to remove the credential type', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const type = await WalletCredentialType.findOne({ where: { id: req.params.typeId, gatewayId: gateway.id } });
  if (!type) throw new InputError('Credential type not found', 404);
  await type.destroy();
  changed(gateway);
  res.json({ message: 'Credential type removed' });
});

// ------------------------------------------------------------------ setup

// Creates what the client needs to call the gateway: a catalog (unless the gateway serves one),
// the built-in API, a published product with it and the "Provider server" application with an
// approved subscription. The client secret is shown once. Safe to run again: existing pieces are reused.
const setup = handle('Failed to set up the wallet APIs', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const builtin = KIND_BUILTIN[gateway.kind];
  const { name: apiName, basePath } = BUILTINS[builtin];
  const result = await sequelize.transaction(async (transaction) => {
    // The gateway's catalog, or the one an earlier setup created before the gateway could be attached.
    const catalogId = gateway.catalogId || gateway.walletSettings?.setupCatalogId;
    let catalog = catalogId ? await Catalog.findOne({ where: { id: catalogId, organizationId: gateway.organizationId }, transaction }) : null;
    if (!catalog) {
      catalog = await Catalog.create({ organizationId: gateway.organizationId, name: `${gateway.name} catalog`.slice(0, 255), description: `Built-in ${apiName} API of ${gateway.name}` }, { transaction });
    }
    const apis = await Api.findAll({ where: { organizationId: gateway.organizationId, catalogId: catalog.id }, transaction });
    let api = apis.find((item) => builtinOf(item.spec) === builtin);
    if (!api) {
      const clash = apis.find((item) => item.basePath === basePath);
      if (clash) throw new InputError(`API "${clash.name}" already uses ${basePath} in this catalog`, 409);
      api = await Api.create({
        organizationId: gateway.organizationId, catalogId: catalog.id, name: apiName, version: '1.0.0',
        description: builtinSpec(builtin).info.description, basePath, access: 'subscription', source: 'manual', spec: builtinSpec(builtin),
      }, { transaction });
      const policy = await Policy.create({
        organizationId: gateway.organizationId, name: `${apiName} policy`, description: 'Built-in wallet API: the gateway answers it itself; this flow is not used.', flow: defaultFlow(), ownerApiId: api.id,
      }, { transaction });
      await api.update({ policyId: policy.id }, { transaction });
    }
    const links = await ProductApi.findAll({ where: { apiId: api.id }, transaction });
    let product = links.length ? await ApiProduct.findOne({ where: { id: links.map((link) => link.productId), organizationId: gateway.organizationId, catalogId: catalog.id }, transaction }) : null;
    if (!product) {
      product = await ApiProduct.create({
        organizationId: gateway.organizationId, catalogId: catalog.id, name: apiName, description: `${apiName} on ${gateway.name}`, status: 'published',
      }, { transaction });
      await ProductApi.create({ productId: product.id, apiId: api.id }, { transaction });
    } else if (product.status !== 'published') {
      await product.update({ status: 'published' }, { transaction });
    }
    let secret = null;
    let application = await Application.findOne({ where: { organizationId: gateway.organizationId, name: `${gateway.name} provider server`.slice(0, 255) }, transaction });
    if (!application) {
      secret = crypto.randomBytes(32).toString('base64url');
      application = await Application.create({
        userId: req.user.id,
        organizationId: gateway.organizationId,
        name: `${gateway.name} provider server`.slice(0, 255),
        description: `The client's provider server: calls ${apiName} on ${gateway.name} with OAuth client credentials.`,
        redirectUris: [],
        clientId: crypto.randomUUID(),
        clientSecret: Application.hashSecret(secret),
        grantTypes: JSON.stringify(['client_credentials']),
      }, { transaction });
    }
    const subscription = await Subscription.findOne({ where: { applicationId: application.id, productId: product.id }, transaction });
    if (!subscription) await Subscription.create({ applicationId: application.id, productId: product.id, status: 'approved', decidedAt: new Date() }, { transaction });
    else if (subscription.status !== 'approved') await subscription.update({ status: 'approved', decidedAt: new Date() }, { transaction });
    await gateway.update({ walletSettings: { ...(gateway.walletSettings || {}), setupCatalogId: catalog.id } }, { transaction });
    return { catalog, api, product, application, secret };
  });

  // A gateway serves a catalog only once it runs (as for API gateways).
  let attached = gateway.catalogId === result.catalog.id;
  if (!attached && await isGatewayRunning(gateway)) {
    await gateway.update({ catalogId: result.catalog.id });
    attached = true;
  }
  changed(gateway);
  res.json({
    catalog: { id: result.catalog.id, name: result.catalog.name },
    api: { id: result.api.id, name: result.api.name, basePath: result.api.basePath },
    product: { id: result.product.id, name: result.product.name },
    application: { id: result.application.id, name: result.application.name, clientId: result.application.clientId, ...(result.secret && { clientSecret: result.secret }) },
    attached,
    ...(!attached && { message: `Start a node of ${gateway.name}, then attach it to the catalog "${result.catalog.name}" (or run Set up again).` }),
  });
});

// ------------------------------------------------------------------ records

const listRecords = handle('Failed to load the records', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const status = typeof req.query.status === 'string' && /^[a-z_]{1,20}$/.test(req.query.status) ? req.query.status : null;
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  const where = { gatewayId: gateway.id, organizationId: gateway.organizationId, ...(status && { status }) };
  if (ROLE[gateway.kind] === 'verifier') {
    const rows = await WalletVerification.findAll({ where, order: [['createdAt', 'DESC']], limit });
    return res.json({
      verifications: rows.map((row) => ({
        id: row.sessionId, clientId: row.clientId, credentialType: row.credentialType, status: row.status, reason: row.reason,
        issuer: row.issuer, reference: row.reference, claimNames: row.claimNames, callback: row.callback, startedAt: row.startedAt, completedAt: row.completedAt,
      })),
    });
  }
  const rows = await WalletIssuedCredential.findAll({ where, order: [['createdAt', 'DESC']], limit });
  res.json({
    credentials: rows.map((row) => ({
      id: row.credentialId, offerId: row.offerId, clientId: row.clientId, credentialType: row.credentialType, subject: row.subject, status: row.status,
      statusIndex: row.statusIndex, node: row.node, claimNames: row.claimNames, issuedAt: row.issuedAt, expiresAt: row.expiresAt,
    })),
  });
});

const ACTIONS = { revoke: 'revoked', suspend: 'suspended', reinstate: 'valid' };
const changeCredentialStatus = handle('Failed to change the credential status', async (req, res) => {
  const gateway = await findWalletGateway(req);
  const next = ACTIONS[req.params.action];
  if (!next) throw new InputError('Use revoke, suspend or reinstate', 404);
  const credential = await WalletIssuedCredential.findOne({ where: { gatewayId: gateway.id, organizationId: gateway.organizationId, credentialId: req.params.credentialId } });
  if (!credential) throw new InputError('Credential not found', 404);
  if (credential.status === 'revoked' && next !== 'revoked') throw new InputError('A revoked credential stays revoked', 409);
  await credential.update({ status: next });
  // The status list is part of the configuration: the change reaches the gateway with the next push.
  changed(gateway);
  res.json({ credential: { id: credential.credentialId, status: credential.status } });
});

module.exports = {
  getWallet,
  updateIdentity,
  removeRegistration,
  updateSettings,
  rotateCallbackSecret,
  createAnchor,
  deleteAnchor,
  createType,
  updateType,
  deleteType,
  setup,
  listRecords,
  changeCredentialStatus,
  describeWallet,
  findWalletGateway,
  InputError,
};
