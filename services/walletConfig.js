// The `wallet` section of a wallet gateway's configuration (schema 3, gateway/src/wallet/index.js
// validates it): the client's certificates and keys, credential types, trust anchors, provider
// server, settings and, for issuers, the status list (entries changed in the console and the
// index range of every node). Problems block a push, each with a link to its fix.
const crypto = require('crypto');
const { WalletTrustAnchor, WalletCredentialType, WalletIssuedCredential } = require('../models');
const { open } = require('../utils/secretBox');

const WALLET_KINDS = ['wallet-verifier', 'wallet-issuer'];
const KINDS = ['api', ...WALLET_KINDS];
const ROLE = { 'wallet-verifier': 'verifier', 'wallet-issuer': 'issuer' };
const ENTITLEMENTS = ['PID', 'QEAA', 'PuB-EAA', 'EAA', 'WalletProvider'];
const LEGAL_CATEGORIES = ['EAA', 'PuB-EAA', 'QEAA'];
const STATUS_VALUES = { valid: 0, revoked: 1, suspended: 2 };
// Each node issues from its own block of the status list, so nodes never share an index.
const STATUS_BLOCK = 16384;
const DEFAULT_LIST_SIZE = 131072;
const EXPIRY_WARNING_DAYS = 30;

const isWallet = (gateway) => WALLET_KINDS.includes(gateway.kind);

const DEFAULT_SETTINGS = {
  clientIdScheme: 'x509_san_dns',
  responseMode: 'direct_post.jwt',
  sessionSeconds: 300,
  resultRetentionHours: 24,
  offerTtlSeconds: 86400,
  batchSize: 1,
  requireWalletAttestation: false,
  verifierInfoFormat: 'registration_cert',
};

const walletSettingsOf = (gateway) => {
  const stored = gateway.walletSettings || {};
  return {
    legalName: stored.legalName || '',
    displayName: stored.displayName || '',
    legalCategory: LEGAL_CATEGORIES.includes(stored.legalCategory) ? stored.legalCategory : 'EAA',
    accessCertificatePem: stored.accessCertificatePem || null,
    issuerCertificatePem: stored.issuerCertificatePem || null,
    registrationCertificates: Array.isArray(stored.registrationCertificates) ? stored.registrationCertificates : [],
    provider: { connectionId: null, callbackUrl: null, claimsUrl: null, ...(stored.provider || {}) },
    settings: { ...DEFAULT_SETTINGS, ...(stored.settings || {}) },
    walletProviderAnchorIds: Array.isArray(stored.walletProviderAnchorIds) ? stored.walletProviderAnchorIds : [],
    statusList: { listId: '1', size: DEFAULT_LIST_SIZE, ...(stored.statusList || {}) },
    statusBlocks: stored.statusBlocks && typeof stored.statusBlocks === 'object' ? stored.statusBlocks : {},
  };
};

const walletSecretsOf = (gateway) => {
  if (!gateway.walletSecretsSealed) return {};
  try {
    return JSON.parse(open(gateway.walletSecretsSealed));
  } catch {
    return {};
  }
};

const certificatesOf = (pem) => String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];

// { subject, subjectAltName, validTo, daysLeft, fingerprint } of the first certificate, or null.
const describeCertificate = (pem) => {
  const [first] = certificatesOf(pem);
  if (!first) return null;
  try {
    const cert = new crypto.X509Certificate(first);
    return {
      subject: cert.subject.split('\n').join(', '),
      issuer: cert.issuer.split('\n').join(', '),
      subjectAltName: cert.subjectAltName || null,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      daysLeft: Math.floor((new Date(cert.validTo).getTime() - Date.now()) / 86400000),
      fingerprint: cert.fingerprint256,
      count: certificatesOf(pem).length,
    };
  } catch {
    return null;
  }
};

// The payload of a registration certificate (a JWT), without verifying it; for display and checks.
const registrationPayload = (jwt) => {
  try {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
};

// Status list blocks for every node, kept in walletSettings so they never move. Returns the
// settings changes to save (null when nothing changed).
const assignStatusBlocks = (gateway, settings) => {
  const blocks = { ...settings.statusBlocks };
  const count = Math.floor(settings.statusList.size / STATUS_BLOCK);
  const taken = new Set(Object.values(blocks));
  let changed = false;
  for (const node of [...(gateway.nodes || [])].sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
    if (blocks[node.name] !== undefined) continue;
    let block = 0;
    while (taken.has(block) && block < count) block += 1;
    if (block >= count) continue;
    blocks[node.name] = block;
    taken.add(block);
    changed = true;
  }
  return changed ? blocks : null;
};

// `gateway` must include nodes. addProblem(message, fix). Returns the wallet section, or null on API gateways.
const buildWalletSection = async (gateway, { addProblem, connections }) => {
  if (!isWallet(gateway)) return null;
  const role = ROLE[gateway.kind];
  const page = `/developer/gateways/${gateway.id}/wallet`;
  const fix = (anchor, label) => ({ href: `${page}#${anchor}`, label });
  const settings = walletSettingsOf(gateway);
  const secrets = walletSecretsOf(gateway);

  const [anchors, types] = await Promise.all([
    WalletTrustAnchor.findAll({ where: { gatewayId: gateway.id, organizationId: gateway.organizationId }, order: [['name', 'ASC']] }),
    WalletCredentialType.findAll({ where: { gatewayId: gateway.id, organizationId: gateway.organizationId }, order: [['key', 'ASC']] }),
  ]);

  const access = describeCertificate(settings.accessCertificatePem);
  if (!access || !secrets.accessKeyPem) {
    addProblem('Upload the access certificate (from your Access CA) and its private key.', fix('identity', 'Add certificates'));
  } else {
    if (access.daysLeft < 0) addProblem('The access certificate has expired. Upload a renewed one.', fix('identity', 'Replace the certificate'));
    if (settings.settings.clientIdScheme === 'x509_san_dns') {
      let host = null;
      try {
        host = new URL(gateway.publicUrl).hostname.toLowerCase();
      } catch {
        host = null;
      }
      const names = String(access.subjectAltName || '').split(/,\s*/).filter((entry) => entry.startsWith('DNS:')).map((entry) => entry.slice(4).toLowerCase());
      if (!host || !names.includes(host)) {
        addProblem(`The access certificate has no DNS name ${host} (the gateway's public URL). Use a certificate for that host, or the x509_hash client ID.`, fix('settings', 'Change the client ID'));
      }
    }
  }
  if (!settings.registrationCertificates.length) {
    addProblem('Add your registration certificate (from your registrar): wallets check the claims you ask for against it.', fix('identity', 'Add a registration certificate'));
  }
  if (role === 'issuer') {
    const issuerCert = describeCertificate(settings.issuerCertificatePem);
    if (!issuerCert || !secrets.issuerKeyPem) addProblem('Upload the issuer certificate and the key that signs your credentials.', fix('identity', 'Add the issuer certificate'));
    else if (issuerCert.daysLeft < 0) addProblem('The issuer certificate has expired. Upload a renewed one.', fix('identity', 'Replace the certificate'));
    if (settings.legalCategory !== 'EAA' && secrets.issuerKeyPem) {
      addProblem(`${settings.legalCategory} issuers sign with a key in their HSM. Software keys are only for EAA; HSM and KMS keys come in a later version.`, fix('identity', 'Change the legal category'));
    }
  }
  if (!types.length) addProblem('Add at least one credential type.', fix('types', 'Add a credential type'));
  const anchorIds = new Set(anchors.map((anchor) => anchor.id));
  if (role === 'verifier') {
    for (const type of types) {
      if (!type.anchorIds.some((id) => anchorIds.has(id))) addProblem(`Credential type "${type.name}" has no trust anchor, so no issuer would be trusted.`, fix('types', `Edit ${type.name}`));
    }
  }
  if (settings.settings.requireWalletAttestation && !settings.walletProviderAnchorIds.some((id) => anchorIds.has(id))) {
    addProblem('Wallet attestations are required but no Wallet Provider trust anchor is chosen.', fix('settings', 'Choose Wallet Provider anchors'));
  }
  const provider = settings.provider;
  if (!provider.callbackUrl) addProblem('Set the callback URL of your provider server.', fix('provider', 'Set up the provider server'));
  if (provider.connectionId && !connections.has(provider.connectionId)) addProblem('The provider server connection no longer exists.', fix('provider', 'Choose a connection'));

  let status;
  if (role === 'issuer') {
    const blocks = assignStatusBlocks(gateway, settings);
    if (blocks) {
      settings.statusBlocks = blocks;
      await gateway.update({ walletSettings: { ...(gateway.walletSettings || {}), statusBlocks: blocks } });
    }
    const ranges = {};
    for (const node of gateway.nodes || []) {
      const block = settings.statusBlocks[node.name];
      if (block !== undefined) ranges[node.name] = [block * STATUS_BLOCK, (block + 1) * STATUS_BLOCK];
    }
    if ((gateway.nodes || []).length === 1 && ranges[gateway.nodes[0].name]) ranges['*'] = ranges[gateway.nodes[0].name];
    if ((gateway.nodes || []).some((node) => !ranges[node.name])) addProblem('The status list has no free block for every node. Remove a node or start a new list.', fix('status', 'Status list'));
    const issued = await WalletIssuedCredential.findAll({
      where: { gatewayId: gateway.id, listId: String(settings.statusList.listId) },
      attributes: ['statusIndex', 'status'],
    });
    const next = {};
    for (const [name, [start, end]] of Object.entries(ranges)) {
      const used = issued.filter((item) => item.statusIndex >= start && item.statusIndex < end).map((item) => item.statusIndex + 1);
      if (used.length) next[name] = Math.max(...used);
    }
    status = {
      listId: String(settings.statusList.listId),
      size: settings.statusList.size,
      entries: issued.filter((item) => item.status !== 'valid').map((item) => [item.statusIndex, STATUS_VALUES[item.status]]).sort((a, b) => a[0] - b[0]),
      ranges,
      next,
    };
  }

  return {
    role,
    identity: {
      legalName: settings.legalName || null,
      displayName: settings.displayName || settings.legalName || null,
      legalCategory: settings.legalCategory,
      accessCertificateChain: settings.accessCertificatePem,
      accessKey: secrets.accessKeyPem ? { provider: 'sealed', privateKey: secrets.accessKeyPem } : null,
      registrationCertificates: settings.registrationCertificates.map((item) => ({ id: item.id, jwt: item.jwt })),
      ...(role === 'issuer' && {
        issuerCertificateChain: settings.issuerCertificatePem,
        issuerKey: secrets.issuerKeyPem ? { provider: 'sealed', privateKey: secrets.issuerKeyPem } : null,
      }),
    },
    settings: settings.settings,
    anchors: anchors.map((anchor) => ({ id: anchor.id, name: anchor.name, entitlement: anchor.entitlement, certificates: anchor.certificatesPem })),
    walletProviderAnchorIds: settings.walletProviderAnchorIds.filter((id) => anchorIds.has(id)),
    credentialTypes: types.map((type) => ({
      id: type.key,
      name: type.name,
      vct: type.vct,
      claims: type.claims,
      anchorIds: type.anchorIds.filter((id) => anchorIds.has(id)),
      validityDays: type.validityDays,
      requireIssuerName: type.requireIssuerName,
      ...(type.display && { display: type.display }),
    })),
    provider: {
      connectionId: provider.connectionId || null,
      callbackUrl: provider.callbackUrl || null,
      claimsUrl: provider.claimsUrl || null,
      callbackSecret: secrets.callbackSecret || null,
    },
    ...(status && { status }),
  };
};

const REDACTED = '[stored encrypted, sent only to the gateway]';
const redactWallet = (wallet) => (wallet ? {
  ...wallet,
  identity: {
    ...wallet.identity,
    ...(wallet.identity.accessKey && { accessKey: { provider: wallet.identity.accessKey.provider, privateKey: REDACTED } }),
    ...(wallet.identity.issuerKey && { issuerKey: { provider: wallet.identity.issuerKey.provider, privateKey: REDACTED } }),
  },
  provider: { ...wallet.provider, ...(wallet.provider.callbackSecret && { callbackSecret: REDACTED }) },
} : wallet);

module.exports = {
  WALLET_KINDS,
  KINDS,
  ROLE,
  ENTITLEMENTS,
  LEGAL_CATEGORIES,
  STATUS_VALUES,
  DEFAULT_SETTINGS,
  isWallet,
  walletSettingsOf,
  walletSecretsOf,
  describeCertificate,
  certificatesOf,
  registrationPayload,
  buildWalletSection,
  redactWallet,
  EXPIRY_WARNING_DAYS,
};
