// Relying Party / Verifier role (OpenID4VP 1.0 with DCQL, SD-JWT VC).
//
//   POST {base}/verifications        provider server: start a verification -> request_uri, deep link
//   GET  {base}/verifications/{id}   provider server: status, reason, claims (until delivered)
//   GET|POST {base}/request/{id}     wallet: the signed request object (served once)
//   POST {base}/response/{id}        wallet: the (encrypted) response; verified, then sent to the provider server
//
// The request object is signed with the client's access certificate key (x5c, client_id prefix
// x509_san_dns or x509_hash). Claims stay in the session store only until the provider server has them.
const crypto = require('crypto');
const { WalletError, b64u, signJws, decryptJwe, parseJson } = require('./jose');
const { verifySdJwtPresentation, pickClaims } = require('./sdjwt');

const QUERY_ID = 'credential';
const REQUEST_TYP = 'oauth-authz-req+jwt';

const json = (status, body, headers = {}) => ({ status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }, body: Buffer.from(JSON.stringify(body)) });
const failure = (status, error, message) => json(status, { error, message });
const randomId = () => b64u(crypto.randomBytes(18));

const parseBody = (ctx) => {
  const type = String(ctx.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const text = ctx.body.toString('utf8');
  if (!text) return {};
  if (type === 'application/x-www-form-urlencoded') return Object.fromEntries(new URLSearchParams(text));
  const parsed = parseJson(text, 'invalid_request', 'request body');
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new WalletError('invalid_request', 'The body must be a JSON object');
  return parsed;
};

// "family_name", "address.locality" or ["address", "locality"] -> path array
const toPath = (value) => (Array.isArray(value) ? value : String(value).split('.'));
const samePath = (a, b) => a.length === b.length && a.every((part, index) => part === b[index]);

const createVerifier = ({ wallet, sessions, statusFetcher, provider, events }) => {
  const { settings, identity } = wallet;
  const key = (id) => `v:${id}`;

  const publicView = (session, { withClaims }) => ({
    id: session.id,
    status: session.status,
    credential_type: session.typeId,
    ...(session.reference && { reference: session.reference }),
    ...(session.reason && { reason: session.reason }),
    ...(session.issuer && { issuer: session.issuer }),
    ...(withClaims && session.claims && { claims: session.claims }),
    ...(session.claimsDelivered && { claims_delivered: true }),
    created_at: session.createdAt,
    expires_at: session.expiresAt,
    ...(session.completedAt && { completed_at: session.completedAt }),
  });

  const record = (session) => events.push({
    type: 'verification',
    id: session.id,
    clientId: session.clientId,
    credentialType: session.typeId,
    status: session.status,
    ...(session.reason && { reason: session.reason }),
    ...(session.issuer && { issuer: session.issuer }),
    ...(session.reference && { reference: session.reference }),
    claimNames: session.claimNames || [],
    createdAt: session.createdAt,
    ...(session.completedAt && { completedAt: session.completedAt }),
  });

  const start = async (ctx, base) => {
    const body = parseBody(ctx);
    const type = wallet.types.get(String(body.credentialType || body.credential_type || ''));
    if (!type) return failure(400, 'invalid_request', `Choose a credential type: ${[...wallet.types.keys()].join(', ') || 'none is configured'}`);
    let claims = type.claims;
    if (body.claims !== undefined) {
      if (!Array.isArray(body.claims) || !body.claims.length || body.claims.length > 100) return failure(400, 'invalid_request', 'claims must be a non-empty list of claim names or paths');
      claims = [];
      for (const item of body.claims) {
        const path = toPath(item);
        const allowed = type.claims.find((claim) => samePath(claim.path, path));
        // Only claims of the type (and so of the registration certificate's intended use) may be asked for.
        if (!allowed) return failure(403, 'claim_not_allowed', `The claim ${path.join('.')} is not one of the claims registered for ${type.id}`);
        claims.push(allowed);
      }
    }
    let redirectUri = null;
    if (body.redirectUri !== undefined || body.redirect_uri !== undefined) {
      try {
        const url = new URL(String(body.redirectUri ?? body.redirect_uri));
        if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) throw new Error('not https');
        redirectUri = url.href;
      } catch {
        return failure(400, 'invalid_request', 'redirectUri must be an https address');
      }
    }
    const reference = body.reference === undefined ? null : String(body.reference).slice(0, 200);
    const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const now = Date.now();
    const session = {
      id: randomId(),
      clientId: ctx.clientId,
      typeId: type.id,
      claims: null,
      requested: claims.map((claim) => ({ path: claim.path, required: claim.required !== false })),
      nonce: b64u(crypto.randomBytes(24)),
      state: b64u(crypto.randomBytes(24)),
      encryptionKey: ephemeral.privateKey.export({ format: 'jwk' }),
      kid: b64u(crypto.randomBytes(8)),
      responseMode: settings.responseMode,
      redirectUri,
      reference,
      status: 'pending',
      requestServed: false,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + settings.sessionSeconds * 1000).toISOString(),
    };
    await sessions.set(key(session.id), session, settings.sessionSeconds);
    record(session);
    const requestUri = `${base}/request/${session.id}`;
    const deepLink = `openid4vp://?${new URLSearchParams({ client_id: identity.clientId, request_uri: requestUri })}`;
    return json(201, {
      id: session.id,
      status: session.status,
      expires_at: session.expiresAt,
      request_uri: requestUri,
      client_id: identity.clientId,
      deep_link: deepLink,
    });
  };

  const get = async (ctx, id) => {
    const session = await sessions.get(key(id));
    // Another application's verification answers like a missing one.
    if (!session || session.clientId !== ctx.clientId) return failure(404, 'not_found', 'No such verification');
    return json(200, publicView(session, { withClaims: true }));
  };

  const requestObject = async (ctx, id, base) => {
    const session = await sessions.get(key(id));
    if (!session) return failure(404, 'not_found', 'This request has expired');
    if (session.requestServed) return failure(410, 'gone', 'This request was already fetched by a wallet');
    session.requestServed = true;
    await sessions.set(key(id), session, Math.max(1, (new Date(session.expiresAt).getTime() - Date.now()) / 1000));
    const type = wallet.types.get(session.typeId);
    const publicJwk = crypto.createPublicKey({ key: session.encryptionKey, format: 'jwk' }).export({ format: 'jwk' });
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: identity.clientId,
      aud: 'https://self-issued.me/v2',
      client_id: identity.clientId,
      response_type: 'vp_token',
      response_mode: session.responseMode,
      response_uri: `${base}/response/${id}`,
      nonce: session.nonce,
      state: session.state,
      iat: now,
      exp: now + settings.sessionSeconds,
      dcql_query: {
        credentials: [{
          id: QUERY_ID,
          format: 'dc+sd-jwt',
          meta: { vct_values: type.vcts },
          claims: session.requested.map((claim) => ({ path: claim.path })),
        }],
      },
      client_metadata: {
        ...(session.responseMode === 'direct_post.jwt' && {
          jwks: { keys: [{ ...publicJwk, kid: session.kid, use: 'enc', alg: 'ECDH-ES' }] },
          encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        }),
        vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': wallet.algs, 'kb-jwt_alg_values': wallet.algs } },
      },
      ...(identity.registrationCertificates.length && {
        verifier_info: identity.registrationCertificates.map((certificate) => ({ format: settings.verifierInfoFormat, data: certificate.jwt, credential_ids: [QUERY_ID] })),
      }),
    };
    const token = signJws({ alg: identity.accessAlg, typ: REQUEST_TYP, x5c: identity.x5c }, payload, identity.accessKey);
    return { status: 200, headers: { 'content-type': 'application/oauth-authz-req+jwt', 'cache-control': 'no-store' }, body: Buffer.from(token) };
  };

  const complete = async (session, outcome) => {
    Object.assign(session, outcome, { completedAt: new Date().toISOString() });
    const ttl = settings.resultRetentionHours * 3600;
    session.expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
    await sessions.set(key(session.id), session, ttl);
    record(session);
    provider.deliver(wallet.provider, {
      event: 'verification.completed',
      id: session.id,
      ...(session.reference && { reference: session.reference }),
      status: session.status,
      credentialType: session.typeId,
      ...(session.reason && { reason: session.reason }),
      ...(session.issuer && { issuer: session.issuer }),
      ...(session.claims && { claims: session.claims }),
    }, {
      // The provider server has the claims: the gateway forgets them.
      onDelivered: async () => {
        const current = await sessions.get(key(session.id));
        if (!current) return;
        current.claims = null;
        current.claimsDelivered = true;
        await sessions.set(key(session.id), current, Math.max(1, (new Date(current.expiresAt).getTime() - Date.now()) / 1000));
      },
    });
  };

  const response = async (ctx, id) => {
    const session = await sessions.get(key(id));
    if (!session) return failure(404, 'not_found', 'This request has expired');
    if (session.status !== 'pending' || !session.requestServed) return failure(400, 'invalid_request', 'This request is not waiting for a response');
    const body = parseBody(ctx);
    let params = body;
    if (session.responseMode === 'direct_post.jwt') {
      if (typeof body.response !== 'string') return failure(400, 'invalid_request', 'Send the encrypted response in the response parameter');
      const { header, plaintext } = decryptJwe(body.response, crypto.createPrivateKey({ key: session.encryptionKey, format: 'jwk' }));
      if (header.kid !== undefined && header.kid !== session.kid) return failure(400, 'invalid_request', 'The response is encrypted to another key');
      params = parseJson(plaintext, 'invalid_request', 'decrypted response');
    }
    if (params.error) {
      await complete(session, { status: 'failed', reason: 'wallet_declined' });
      return json(200, session.redirectUri ? { redirect_uri: session.redirectUri } : {});
    }
    if (params.state !== undefined && params.state !== session.state) return failure(400, 'invalid_request', 'The response does not belong to this request (state)');
    let vpToken = params.vp_token;
    if (typeof vpToken === 'string') {
      try {
        vpToken = JSON.parse(vpToken);
      } catch {
        return failure(400, 'invalid_request', 'vp_token must be a JSON object keyed by credential query id');
      }
    }
    const presentations = vpToken && typeof vpToken === 'object' ? vpToken[QUERY_ID] : null;
    const presentation = Array.isArray(presentations) ? presentations[0] : null;
    const type = wallet.types.get(session.typeId);
    try {
      if (typeof presentation !== 'string') throw new WalletError('format_unsupported', 'The response holds no SD-JWT VC for the requested credential');
      const verified = verifySdJwtPresentation(presentation, {
        anchors: type.anchors,
        vcts: type.vcts,
        nonce: session.nonce,
        audience: identity.clientId,
        requireIssuerName: type.requireIssuerName,
        algs: wallet.algs,
      });
      await statusFetcher.check(verified.status, type.anchors);
      const claims = pickClaims(verified.claims, session.requested);
      await complete(session, {
        status: 'verified',
        issuer: verified.issuer,
        claims,
        claimNames: session.requested.map((claim) => claim.path.join('.')),
      });
    } catch (error) {
      if (!(error instanceof WalletError)) throw error;
      await complete(session, { status: 'failed', reason: error.code });
    }
    return json(200, session.redirectUri ? { redirect_uri: session.redirectUri } : {});
  };

  // ctx: { method, operationPath, params, headers, body, clientId }
  const handle = async (ctx, base) => {
    const route = `${ctx.method} ${ctx.operationPath}`;
    switch (route) {
      case 'POST /verifications': return start(ctx, base);
      case 'GET /verifications/{id}': return get(ctx, ctx.params.id);
      case 'GET /request/{id}':
      case 'POST /request/{id}': return requestObject(ctx, ctx.params.id, base);
      case 'POST /response/{id}': return response(ctx, ctx.params.id);
      default: return failure(404, 'not_found', 'This operation is not part of the verification API');
    }
  };

  return { handle };
};

module.exports = { createVerifier, QUERY_ID };
