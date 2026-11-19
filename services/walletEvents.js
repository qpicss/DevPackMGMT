// Stores the events wallet gateways report with their usage (gateway/src/wallet): verifications,
// issued credentials, status changes made by the provider server and callback outcomes.
// Metadata only: the gateway never sends claim values, and nothing here would store them.
const { WalletVerification, WalletIssuedCredential } = require('../models');
const { isWallet } = require('./walletConfig');

const MAX_EVENTS = 50000;
const VERIFICATION_STATUSES = ['pending', 'verified', 'failed', 'expired'];
const CREDENTIAL_STATUSES = ['valid', 'revoked', 'suspended'];
const ID = /^[A-Za-z0-9_-]{1,64}$/;

const str = (value, max) => (typeof value === 'string' ? value.slice(0, max) : null);
const date = (value) => {
  const parsed = value ? new Date(value) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed : null;
};
const names = (value) => (Array.isArray(value) ? value.filter((item) => typeof item === 'string').map((item) => item.slice(0, 200)).slice(0, 100) : []);

// Returns the number of events stored.
const recordWalletEvents = async (gateway, events) => {
  if (!isWallet(gateway) || !Array.isArray(events) || !events.length) return 0;
  const base = { organizationId: gateway.organizationId, gatewayId: gateway.id };
  let stored = 0;
  let statusChanged = false;
  for (const event of events.slice(0, MAX_EVENTS)) {
    if (!event || typeof event !== 'object' || !ID.test(String(event.id || ''))) continue;
    if (event.type === 'verification' && gateway.kind === 'wallet-verifier' && VERIFICATION_STATUSES.includes(event.status)) {
      const fields = {
        clientId: str(event.clientId, 255),
        credentialType: str(event.credentialType, 64),
        status: event.status,
        reason: str(event.reason, 64),
        issuer: str(event.issuer, 500),
        reference: str(event.reference, 200),
        claimNames: names(event.claimNames),
        startedAt: date(event.createdAt),
        completedAt: date(event.completedAt),
      };
      const existing = await WalletVerification.findOne({ where: { gatewayId: gateway.id, sessionId: event.id } });
      // Events of one verification may arrive from several nodes; a final state is never undone.
      if (existing) {
        if (existing.status === 'pending' || fields.status !== 'pending') await existing.update(fields);
      } else {
        await WalletVerification.create({ ...base, sessionId: event.id, ...fields });
      }
      stored += 1;
    } else if (event.type === 'issued' && gateway.kind === 'wallet-issuer' && Number.isInteger(event.statusIndex) && event.statusIndex >= 0) {
      const existing = await WalletIssuedCredential.findOne({ where: { gatewayId: gateway.id, credentialId: event.id } });
      if (!existing) {
        await WalletIssuedCredential.create({
          ...base,
          credentialId: event.id,
          offerId: str(event.offerId, 64),
          clientId: str(event.clientId, 255),
          credentialType: str(event.credentialType, 64),
          subject: str(event.subject, 200),
          listId: String(event.listId || '1').slice(0, 40),
          statusIndex: event.statusIndex,
          node: str(event.node, 255),
          status: 'valid',
          claimNames: names(event.claimNames),
          issuedAt: date(event.issuedAt),
          expiresAt: date(event.expiresAt),
        });
        stored += 1;
      }
    } else if (event.type === 'credentialStatus' && gateway.kind === 'wallet-issuer' && CREDENTIAL_STATUSES.includes(event.status)) {
      const credential = await WalletIssuedCredential.findOne({ where: { gatewayId: gateway.id, credentialId: event.id } });
      if (credential && credential.status !== 'revoked' && credential.status !== event.status) {
        await credential.update({ status: event.status });
        statusChanged = true;
        stored += 1;
      }
    } else if (event.type === 'callback' && gateway.kind === 'wallet-verifier' && String(event.event || '').startsWith('verification.')) {
      const outcome = event.outcome === 'delivered' ? 'delivered' : 'failed';
      await WalletVerification.update({ callback: outcome }, { where: { gatewayId: gateway.id, sessionId: event.id } });
      stored += 1;
    }
  }
  // Status changes from the provider server reach every node through the configuration.
  // Loaded here: autoPush -> gatewayPush -> this module.
  if (statusChanged) require('./autoPush').scheduleAutoPush(gateway.organizationId);
  return stored;
};

module.exports = { recordWalletEvents };
