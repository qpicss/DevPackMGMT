// Upstream connections: how the gateway reaches an API's backend.
// Each connection configured in the console has its own pooled agent (with optional mTLS and custom
// CAs), timeouts, retries for idempotent methods, credentials and a circuit breaker. APIs without a
// connection use the defaults.
const http = require('http');
const https = require('https');
const tls = require('tls');
const { HttpError } = require('./http');

const IDEMPOTENT = new Set(['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']);
const RETRYABLE_ERRORS = new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'UND_ERR_SOCKET']);
const DEFAULT_ID = '__default';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const defaultsFor = (settings) => ({
  id: DEFAULT_ID,
  name: 'default',
  connectTimeoutMs: 5000,
  timeoutMs: settings.upstreamTimeoutMs,
  retries: 0,
  retryOn: [502, 503, 504],
  circuitBreaker: { enabled: false, failureThreshold: 5, cooldownMs: 30000 },
  auth: { type: 'none' },
  tls: { rejectUnauthorized: true },
});

const buildAgents = (connection) => {
  const options = { keepAlive: true, maxSockets: 100, maxFreeSockets: 20 };
  const tlsOptions = connection.tls || {};
  const httpsOptions = {
    ...options,
    rejectUnauthorized: tlsOptions.rejectUnauthorized !== false,
    // Custom CAs are added to, not substituted for, the system trust store.
    ...(tlsOptions.ca && { ca: [...tls.rootCertificates, tlsOptions.ca] }),
    ...(tlsOptions.clientCertificate && tlsOptions.clientKey && { cert: tlsOptions.clientCertificate, key: tlsOptions.clientKey }),
    ...(tlsOptions.serverName && { servername: tlsOptions.serverName }),
  };
  return { http: new http.Agent(options), https: new https.Agent(httpsOptions) };
};

// Static credentials. OAuth client credentials ('oauth2') need a token first: see credentialHeaders().
const authHeaders = (auth = {}) => {
  switch (auth.type) {
    case 'basic':
      return { authorization: `Basic ${Buffer.from(`${auth.username || ''}:${auth.secret || ''}`).toString('base64')}` };
    case 'bearer':
      return { authorization: `Bearer ${auth.secret || ''}` };
    case 'header':
      return auth.headerName ? { [auth.headerName.toLowerCase()]: auth.secret || '' } : {};
    default:
      return {};
  }
};

class UpstreamConnections {
  constructor({ settings, metrics, logger }) {
    this.settings = settings;
    this.metrics = metrics;
    this.logger = logger;
    this.entries = new Map();
    this.entries.set(DEFAULT_ID, this.createEntry(defaultsFor(settings)));
  }

  createEntry(config) {
    return {
      config,
      fingerprint: JSON.stringify(config),
      agents: buildAgents(config),
      breaker: { failures: 0, openUntil: 0, state: 'closed' },
    };
  }

  // Keeps agents and breaker state for connections that did not change.
  configure(connections = []) {
    const wanted = new Set([DEFAULT_ID]);
    for (const connection of connections) {
      wanted.add(connection.id);
      const config = { ...defaultsFor(this.settings), ...connection, circuitBreaker: { ...defaultsFor(this.settings).circuitBreaker, ...(connection.circuitBreaker || {}) } };
      const existing = this.entries.get(connection.id);
      if (existing && existing.fingerprint === JSON.stringify(config)) continue;
      if (existing) this.destroy(existing);
      this.entries.set(connection.id, this.createEntry(config));
    }
    for (const [id, entry] of this.entries) {
      if (!wanted.has(id)) {
        this.destroy(entry);
        this.entries.delete(id);
      }
    }
  }

  destroy(entry) {
    entry.agents.http.destroy();
    entry.agents.https.destroy();
  }

  get(connectionId) {
    return this.entries.get(connectionId) || this.entries.get(DEFAULT_ID);
  }

  // The headers that authenticate a call through this connection. For 'oauth2' (client
  // credentials) the access token is fetched from the token URL and cached until shortly before
  // it expires; concurrent callers share one token request.
  async credentialHeaders(entry) {
    const auth = entry.config.auth || {};
    if (auth.type !== 'oauth2') return authHeaders(auth);
    if (entry.token && entry.token.until > Date.now()) return { authorization: `Bearer ${entry.token.value}` };
    entry.tokenRequest ||= this.fetchToken(entry).finally(() => { entry.tokenRequest = null; });
    const token = await entry.tokenRequest;
    return { authorization: `Bearer ${token}` };
  }

  forgetToken(entry) {
    entry.token = null;
  }

  async fetchToken(entry) {
    const auth = entry.config.auth;
    const form = new URLSearchParams({ grant_type: 'client_credentials' });
    if (auth.scope) form.set('scope', auth.scope);
    if (auth.audience) form.set('audience', auth.audience);
    const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
    if (auth.clientAuthMethod === 'client_secret_post') {
      form.set('client_id', auth.clientId || '');
      form.set('client_secret', auth.secret || '');
    } else {
      const encode = (value) => encodeURIComponent(value || '');
      headers.authorization = `Basic ${Buffer.from(`${encode(auth.clientId)}:${encode(auth.secret)}`).toString('base64')}`;
    }
    const body = Buffer.from(form.toString());
    let target;
    try {
      target = new URL(auth.tokenUrl);
    } catch {
      throw new HttpError(502, 'upstream_auth_failed', `Connection "${entry.config.name}" has no valid token URL`);
    }
    headers.host = target.host;
    headers['content-length'] = String(body.length);
    const response = await this.send(entry, { target, method: 'POST', headers, body });
    const chunks = [];
    let size = 0;
    for await (const chunk of response) {
      size += chunk.length;
      if (size > 256 * 1024) break;
      chunks.push(chunk);
    }
    let json = null;
    try {
      json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      json = null;
    }
    if (response.statusCode !== 200 || !json || typeof json.access_token !== 'string') {
      this.logger.warn('connection token request failed', { connection: entry.config.name, status: response.statusCode });
      throw new HttpError(502, 'upstream_auth_failed', `Connection "${entry.config.name}" could not get an access token (the token endpoint answered ${response.statusCode})`);
    }
    const lifetime = Number(json.expires_in) > 0 ? Number(json.expires_in) : 300;
    // Renewed 30 seconds (or a tenth of a short lifetime) before it expires.
    entry.token = { value: json.access_token, until: Date.now() + Math.max(1, lifetime - Math.min(30, lifetime / 10)) * 1000 };
    return json.access_token;
  }

  status() {
    return [...this.entries.values()]
      .filter((entry) => entry.config.id !== DEFAULT_ID)
      .map((entry) => ({ id: entry.config.id, name: entry.config.name, circuit: entry.breaker.state, failures: entry.breaker.failures }));
  }

  breakerAllows(entry) {
    const { breaker, config } = entry;
    if (!config.circuitBreaker.enabled || breaker.state === 'closed') return true;
    if (breaker.state === 'open' && Date.now() >= breaker.openUntil) {
      breaker.state = 'half-open';
      return true;
    }
    return breaker.state === 'half-open' ? false : Date.now() >= breaker.openUntil;
  }

  recordResult(entry, failed) {
    const { breaker, config } = entry;
    if (!config.circuitBreaker.enabled) return;
    if (!failed) {
      if (breaker.state !== 'closed') this.logger.info('circuit closed', { connection: config.name });
      breaker.failures = 0;
      breaker.state = 'closed';
      this.metrics.circuitOpen.set({ connection: config.name }, 0);
      return;
    }
    breaker.failures += 1;
    if (breaker.state === 'half-open' || breaker.failures >= config.circuitBreaker.failureThreshold) {
      breaker.state = 'open';
      breaker.openUntil = Date.now() + config.circuitBreaker.cooldownMs;
      this.metrics.circuitOpen.set({ connection: config.name }, 1);
      this.logger.warn('circuit opened', { connection: config.name, failures: breaker.failures, cooldownMs: config.circuitBreaker.cooldownMs });
    }
  }

  once(entry, { target, method, headers, body, timeoutMs }) {
    const { config } = entry;
    const responseTimeoutMs = timeoutMs || config.timeoutMs;
    const transport = target.protocol === 'https:' ? https : http;
    const agent = target.protocol === 'https:' ? entry.agents.https : entry.agents.http;
    return new Promise((resolve, reject) => {
      const request = transport.request(target, { method, headers, agent }, resolve);
      request.on('socket', (socket) => {
        if (!socket.connecting) return;
        const timer = setTimeout(() => request.destroy(Object.assign(new Error('connect timeout'), { code: 'CONNECT_TIMEOUT' })), config.connectTimeoutMs);
        socket.once(target.protocol === 'https:' ? 'secureConnect' : 'connect', () => clearTimeout(timer));
        socket.once('close', () => clearTimeout(timer));
      });
      request.setTimeout(responseTimeoutMs, () => {
        request.destroy(Object.assign(new Error('response timeout'), { code: 'RESPONSE_TIMEOUT' }));
      });
      request.on('error', reject);
      request.end(body);
    });
  }

  // Sends the request with retries and circuit breaking. Resolves to the upstream response stream.
  // `request.timeoutMs` overrides the connection's response timeout.
  async send(entry, request) {
    const { config } = entry;
    if (!this.breakerAllows(entry)) {
      throw new HttpError(503, 'circuit_open', 'The upstream is failing and temporarily not called. Try again shortly.', {
        'retry-after': String(Math.max(1, Math.ceil((entry.breaker.openUntil - Date.now()) / 1000))),
      });
    }

    const attempts = IDEMPOTENT.has(request.method) ? Math.max(0, config.retries) + 1 : 1;
    for (let attempt = 1; ; attempt += 1) {
      try {
        const response = await this.once(entry, request);
        const retryable = config.retryOn.includes(response.statusCode);
        if (retryable && attempt < attempts) {
          response.resume();
          await sleep(100 * 2 ** (attempt - 1));
          continue;
        }
        this.recordResult(entry, retryable && response.statusCode >= 500);
        return response;
      } catch (error) {
        const retryable = RETRYABLE_ERRORS.has(error.code) || error.code === 'CONNECT_TIMEOUT';
        if (retryable && attempt < attempts) {
          await sleep(100 * 2 ** (attempt - 1));
          continue;
        }
        this.recordResult(entry, true);
        if (error.code === 'CONNECT_TIMEOUT') throw new HttpError(504, 'upstream_timeout', `The upstream did not accept a connection within ${config.connectTimeoutMs} ms`);
        if (error.code === 'RESPONSE_TIMEOUT') throw new HttpError(504, 'upstream_timeout', `The upstream did not respond within ${request.timeoutMs || config.timeoutMs} ms`);
        if (error.code && /CERT|SELF_SIGNED|UNABLE_TO|ERR_TLS/.test(error.code)) {
          throw new HttpError(502, 'upstream_tls_error', 'The upstream certificate could not be verified');
        }
        throw new HttpError(502, 'bad_gateway', 'The upstream could not be reached');
      }
    }
  }

  closeAll() {
    for (const entry of this.entries.values()) this.destroy(entry);
  }
}

module.exports = { UpstreamConnections, authHeaders, DEFAULT_ID };
