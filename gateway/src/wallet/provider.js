// Calls to the client's provider server: callbacks (signed with HMAC, retried) and, for issuers,
// fetching the claims of a credential at redemption time. Both go through the configured
// connection, so its OAuth client credentials, mTLS certificate and timeouts apply.
const crypto = require('crypto');

const RETRY_DELAYS_MS = [5000, 30000, 120000, 600000, 3600000];
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_PENDING = 10000;

const readAll = (response, limit = MAX_RESPONSE_BYTES) => new Promise((resolve, reject) => {
  const chunks = [];
  let size = 0;
  response.on('data', (chunk) => {
    size += chunk.length;
    if (size > limit) {
      response.destroy();
      reject(new Error('The provider server answered with too much data'));
      return;
    }
    chunks.push(chunk);
  });
  response.on('end', () => resolve(Buffer.concat(chunks)));
  response.on('error', reject);
});

// X-Wallet-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">
const signatureHeader = (secret, body, now = Date.now()) => {
  const t = Math.floor(now / 1000);
  const v1 = crypto.createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return `t=${t},v1=${v1}`;
};

const createProviderClient = ({ connections, logger, events, retryDelaysMs = RETRY_DELAYS_MS }) => {
  let pending = 0;

  // POSTs JSON; returns { status, json }. On a 401 the connection's OAuth token is renewed once.
  const post = async (provider, url, payload) => {
    const entry = connections.get(provider.connectionId);
    const body = Buffer.from(JSON.stringify(payload));
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const headers = {
        'content-type': 'application/json',
        accept: 'application/json',
        'content-length': String(body.length),
        'user-agent': 'phylax-wallet-gateway',
        ...(provider.callbackSecret && { 'x-wallet-signature': signatureHeader(provider.callbackSecret, body.toString('utf8')) }),
        ...(await connections.credentialHeaders(entry)),
      };
      const target = new URL(url);
      headers.host = target.host;
      const response = await connections.send(entry, { target, method: 'POST', headers, body });
      const buffer = await readAll(response);
      if (response.statusCode === 401 && attempt === 0 && entry.config.auth?.type === 'oauth2') {
        connections.forgetToken(entry);
        continue;
      }
      let json = null;
      try {
        json = buffer.length ? JSON.parse(buffer.toString('utf8')) : null;
      } catch {
        json = null;
      }
      return { status: response.statusCode, json };
    }
    return { status: 401, json: null };
  };

  // Delivers an event to the callback URL; retried on failure, then reported as failed.
  // onDelivered runs once the provider server answered 2xx.
  const deliver = (provider, event, { onDelivered } = {}) => {
    if (!provider?.callbackUrl) return;
    if (pending >= MAX_PENDING) {
      logger.warn('wallet callback dropped: too many pending', { event: event.event });
      events.push({ type: 'callback', event: event.event, id: event.id, outcome: 'failed', attempts: 0 });
      return;
    }
    pending += 1;
    const attempt = async (count) => {
      let ok = false;
      let reason = null;
      try {
        const { status } = await post(provider, provider.callbackUrl, event);
        ok = status >= 200 && status < 300;
        if (!ok) reason = `answered ${status}`;
      } catch (error) {
        reason = error.message;
      }
      if (ok) {
        pending -= 1;
        events.push({ type: 'callback', event: event.event, id: event.id, outcome: 'delivered', attempts: count + 1 });
        try {
          await onDelivered?.();
        } catch (error) {
          logger.warn('wallet callback follow-up failed', { error: error.message });
        }
        return;
      }
      if (count < retryDelaysMs.length) {
        const timer = setTimeout(() => attempt(count + 1), retryDelaysMs[count]);
        timer.unref?.();
        return;
      }
      pending -= 1;
      logger.warn('wallet callback failed', { event: event.event, id: event.id, reason });
      events.push({ type: 'callback', event: event.event, id: event.id, outcome: 'failed', attempts: count + 1, reason: String(reason).slice(0, 200) });
    };
    attempt(0);
  };

  return { post, deliver, status: () => ({ pendingCallbacks: pending }) };
};

module.exports = { createProviderClient, signatureHeader, RETRY_DELAYS_MS };
