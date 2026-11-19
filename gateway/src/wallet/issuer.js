// Attestation Provider role (OpenID4VCI 1.0, pre-authorized code flow, SD-JWT VC).
//
// Provider server (gateway token + subscription):
//   POST {base}/offers                      create an offer -> credential_offer_uri, deep link, tx_code
//   GET  {base}/offers/{id}                 pending | redeemed | expired, issued credential ids
//   POST {base}/credentials/{id}/{action}   revoke | suspend | reinstate (id = "<list>-<index>")
// Wallets (public):
//   GET  /.well-known/openid-credential-issuer{base} (and {base}/.well-known/...)   signed issuer metadata
//   GET  /.well-known/oauth-authorization-server{base} (and {base}/.well-known/...) authorization server metadata
//   GET  {base}/credential-offer/{id}       the offer
//   POST {base}/token                       pre-authorized_code (+ tx_code) -> access token (DPoP-bound if a proof is sent)
//   POST {base}/nonce                       c_nonce
//   POST {base}/credential                  proofs -> SD-JWT VC(s), claims fetched from the provider server
//   GET  {base}/status/{listId}             the client's Token Status List, signed with the issuer key
const crypto = require('crypto');
const { WalletError, b64u, sha256, signJws, decodeJws, verifySignature, toKeyObject, parseJson, certificatesFromX5c, validateChain } = require('./jose');
const { issueSdJwt } = require('./sdjwt');
const { signStatusList, STATUS } = require('./statusList');

const PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const PROOF_TYP = 'openid4vci-proof+jwt';
const TOKEN_SECONDS = 300;
const NONCE_SECONDS = 300;
const PROOF_MAX_AGE_SECONDS = 300;
const STATUS_CACHE_MS = 30000;
const MAX_TX_FAILURES = 5;

const json = (status, body, headers = {}) => ({ status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }, body: Buffer.from(JSON.stringify(body)) });
const oauthError = (status, error, description, headers) => json(status, { error, error_description: description }, headers);
const randomToken = (bytes = 32) => b64u(crypto.randomBytes(bytes));
const hashOf = (value) => b64u(sha256(Buffer.from(String(value))));
// Compares a value with a stored hash in constant time.
const matchesHash = (value, hash) => {
  const left = Buffer.from(hashOf(value));
  const right = Buffer.from(String(hash));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};

const parseBody = (ctx) => {
  const type = String(ctx.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const text = ctx.body.toString('utf8');
  if (!text) return {};
  if (type === 'application/x-www-form-urlencoded') return Object.fromEntries(new URLSearchParams(text));
  const parsed = parseJson(text, 'invalid_request', 'request body');
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new WalletError('invalid_request', 'The body must be a JSON object');
  return parsed;
};

// DPoP proof (RFC 9449): returns the JWK thumbprint the token is bound to, or null without a proof.
const jwkThumbprint = (jwk) => {
  const members = jwk.kty === 'EC' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    : jwk.kty === 'RSA' ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return b64u(sha256(Buffer.from(JSON.stringify(members))));
};

const checkDpop = (proof, { method, url, accessToken, algs }) => {
  const decoded = decodeJws(proof, 'invalid_dpop_proof');
  const { header, payload } = decoded;
  if (header.typ !== 'dpop+jwt' || !header.jwk || header.jwk.d) throw new WalletError('invalid_dpop_proof', 'The DPoP proof header is not valid');
  if (!verifySignature(decoded, toKeyObject(header.jwk, 'public'), algs)) throw new WalletError('invalid_dpop_proof', 'The DPoP proof signature does not match');
  const now = Math.floor(Date.now() / 1000);
  if (payload.htm !== method || payload.htu !== url || !payload.jti || !(Math.abs(now - Number(payload.iat)) <= PROOF_MAX_AGE_SECONDS)) {
    throw new WalletError('invalid_dpop_proof', 'The DPoP proof does not match this request');
  }
  if (accessToken !== undefined && payload.ath !== hashOf(accessToken)) throw new WalletError('invalid_dpop_proof', 'The DPoP proof is not bound to this access token');
  return { thumbprint: jwkThumbprint(header.jwk), jti: payload.jti };
};

// `overlay`: status changes made through the API on this node, kept (across configurations) until
// the console's configuration carries them.
const createIssuer = ({ wallet, sessions, provider, events, statusAllocator, overlay = new Map() }) => {
  const { settings, identity, issuer } = wallet;
  let statusCache = null;

  const credentialIssuerOf = (base) => base;
  const configurationId = (type) => type.id;

  const metadata = (base) => {
    const body = {
      credential_issuer: credentialIssuerOf(base),
      credential_endpoint: `${base}/credential`,
      nonce_endpoint: `${base}/nonce`,
      display: [{ name: issuer.displayName, locale: 'en' }],
      credential_configurations_supported: Object.fromEntries([...wallet.types.values()].map((type) => [configurationId(type), {
        format: 'dc+sd-jwt',
        vct: type.vcts[0],
        scope: type.id,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: [issuer.alg],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: wallet.algs } },
        ...(type.display && { credential_metadata: { display: [type.display] } }),
        claims: type.claims.map((claim) => ({ path: claim.path, mandatory: claim.required !== false, ...(claim.label && { display: [{ name: claim.label, locale: 'en' }] }) })),
      }])),
    };
    if (settings.batchSize > 1) body.batch_credential_issuance = { batch_size: settings.batchSize };
    // Signed metadata (OpenID4VCI 1.0 section 12.2.3), signed with the access certificate (ETSI TS 119 472-3).
    const now = Math.floor(Date.now() / 1000);
    body.signed_metadata = signJws({ alg: identity.accessAlg, typ: 'openidvci-issuer-metadata+jwt', x5c: identity.x5c }, {
      ...body, iss: identity.subject || base, sub: base, iat: now, exp: now + 86400,
      ...(identity.registrationCertificates.length && { registration_certificates: identity.registrationCertificates.map((item) => item.jwt) }),
    }, identity.accessKey);
    return json(200, body, { 'cache-control': 'max-age=60' });
  };

  const authorizationServer = (base) => json(200, {
    issuer: base,
    token_endpoint: `${base}/token`,
    grant_types_supported: [PRE_AUTHORIZED],
    'pre-authorized_grant_anonymous_access_supported': true,
    dpop_signing_alg_values_supported: wallet.algs,
    ...(settings.requireWalletAttestation && { token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'] }),
  }, { 'cache-control': 'max-age=60' });

  const recordOffer = (offer) => events.push({
    type: 'offer', id: offer.id, clientId: offer.clientId, credentialType: offer.typeId, subject: offer.subject,
    status: offer.status, createdAt: offer.createdAt, ...(offer.redeemedAt && { redeemedAt: offer.redeemedAt }),
  });

  const createOffer = async (ctx, base) => {
    const body = parseBody(ctx);
    const type = wallet.types.get(String(body.credentialType || body.credential_type || ''));
    if (!type) return json(400, { error: 'invalid_request', message: `Choose a credential type: ${[...wallet.types.keys()].join(', ') || 'none is configured'}` });
    const subject = body.subject === undefined ? '' : String(body.subject).slice(0, 200);
    if (!subject) return json(400, { error: 'invalid_request', message: 'subject (your reference for the person) is required' });
    let claims = null;
    if (body.claims !== undefined) {
      if (!body.claims || typeof body.claims !== 'object' || Array.isArray(body.claims)) return json(400, { error: 'invalid_request', message: 'claims must be an object' });
      const missing = type.claims.filter((claim) => claim.required !== false && body.claims[claim.path[0]] === undefined);
      if (missing.length) return json(400, { error: 'invalid_request', message: `Missing claims: ${missing.map((claim) => claim.path.join('.')).join(', ')}` });
      const known = new Set(type.claims.map((claim) => claim.path[0]));
      const unknown = Object.keys(body.claims).filter((name) => !known.has(name));
      if (unknown.length) return json(400, { error: 'invalid_request', message: `Claims not in ${type.id}: ${unknown.join(', ')}` });
      claims = body.claims;
    } else if (!wallet.provider.claimsUrl) {
      return json(400, { error: 'invalid_request', message: 'Send the claims, or configure a claims URL on the provider server' });
    }
    const txCode = body.txCode === true || body.tx_code === true ? String(crypto.randomInt(0, 1000000)).padStart(6, '0') : null;
    const now = Date.now();
    const offer = {
      id: randomToken(18),
      code: randomToken(32),
      clientId: ctx.clientId,
      typeId: type.id,
      subject,
      claims,
      ...(txCode && { txCodeHash: hashOf(txCode) }),
      status: 'pending',
      credentialIds: [],
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + settings.offerTtlSeconds * 1000).toISOString(),
    };
    await sessions.set(`o:${offer.id}`, offer, settings.offerTtlSeconds + 86400);
    await sessions.set(`c:${offer.code}`, offer.id, settings.offerTtlSeconds);
    recordOffer(offer);
    const offerUri = `${base}/credential-offer/${offer.id}`;
    return json(201, {
      offer_id: offer.id,
      credential_offer_uri: offerUri,
      deep_link: `openid-credential-offer://?${new URLSearchParams({ credential_offer_uri: offerUri })}`,
      expires_at: offer.expiresAt,
      ...(txCode && { tx_code: txCode }),
    });
  };

  const loadOffer = async (id) => {
    const offer = await sessions.get(`o:${id}`);
    if (offer && offer.status === 'pending' && new Date(offer.expiresAt).getTime() <= Date.now()) {
      offer.status = 'expired';
      await sessions.set(`o:${id}`, offer, 86400);
      recordOffer(offer);
      provider.deliver(wallet.provider, { event: 'offer.expired', id: offer.id, subject: offer.subject, credentialType: offer.typeId });
    }
    return offer;
  };

  const getOffer = async (ctx, id) => {
    const offer = await loadOffer(id);
    if (!offer || offer.clientId !== ctx.clientId) return json(404, { error: 'not_found', message: 'No such offer' });
    return json(200, {
      offer_id: offer.id, status: offer.status, credential_type: offer.typeId, subject: offer.subject,
      credential_ids: offer.credentialIds, created_at: offer.createdAt, expires_at: offer.expiresAt,
      ...(offer.redeemedAt && { redeemed_at: offer.redeemedAt }),
    });
  };

  const credentialOffer = async (id, base) => {
    const offer = await loadOffer(id);
    if (!offer || offer.status !== 'pending') return json(404, { error: 'not_found', message: 'This offer is no longer available' });
    return json(200, {
      credential_issuer: credentialIssuerOf(base),
      credential_configuration_ids: [offer.typeId],
      grants: {
        [PRE_AUTHORIZED]: {
          'pre-authorized_code': offer.code,
          ...(offer.txCodeHash && { tx_code: { input_mode: 'numeric', length: 6, description: 'Enter the code you received from the issuer' } }),
        },
      },
    });
  };

  // OAuth 2.0 Attestation-Based Client Authentication: the Wallet Provider's attestation of the
  // wallet instance, checked against the Wallet Provider trust anchors, plus its proof of possession.
  const checkWalletAttestation = (ctx, base) => {
    const attestation = ctx.headers['oauth-client-attestation'];
    const pop = ctx.headers['oauth-client-attestation-pop'];
    if (!attestation || !pop) throw new WalletError('invalid_client', 'A wallet attestation is required');
    const decoded = decodeJws(attestation, 'invalid_client');
    let leaf;
    try {
      ({ leaf } = validateChain(certificatesFromX5c(decoded.header.x5c), wallet.walletProviderAnchors));
    } catch {
      throw new WalletError('invalid_client', 'The wallet attestation is not from a trusted Wallet Provider');
    }
    if (!verifySignature(decoded, leaf.publicKey, wallet.algs)) throw new WalletError('invalid_client', 'The wallet attestation signature does not match');
    const now = Math.floor(Date.now() / 1000);
    if (!(Number(decoded.payload.exp) > now) || !decoded.payload.cnf?.jwk) throw new WalletError('invalid_client', 'The wallet attestation has expired or names no key');
    const proof = decodeJws(pop, 'invalid_client');
    if (!verifySignature(proof, toKeyObject(decoded.payload.cnf.jwk, 'public'), wallet.algs)) throw new WalletError('invalid_client', 'The wallet attestation proof does not match');
    if (proof.payload.aud !== base || !proof.payload.jti || !(Math.abs(now - Number(proof.payload.iat)) <= PROOF_MAX_AGE_SECONDS)) {
      throw new WalletError('invalid_client', 'The wallet attestation proof is not for this issuer or not fresh');
    }
    return decoded.payload.sub || null;
  };

  const token = async (ctx, base) => {
    const body = parseBody(ctx);
    if (body.grant_type !== PRE_AUTHORIZED) return oauthError(400, 'unsupported_grant_type', 'Only the pre-authorized code grant is supported');
    try {
      if (settings.requireWalletAttestation) checkWalletAttestation(ctx, base);
    } catch (error) {
      if (error instanceof WalletError) return oauthError(401, 'invalid_client', error.message);
      throw error;
    }
    let dpop = null;
    if (ctx.headers.dpop) {
      try {
        dpop = checkDpop(ctx.headers.dpop, { method: 'POST', url: `${base}/token`, algs: wallet.algs });
      } catch (error) {
        if (error instanceof WalletError) return oauthError(400, 'invalid_dpop_proof', error.message);
        throw error;
      }
    }
    const codeKey = `c:${String(body['pre-authorized_code'] || '')}`;
    const offerId = await sessions.get(codeKey);
    const offer = offerId ? await loadOffer(offerId) : null;
    if (!offer || offer.status !== 'pending') return oauthError(400, 'invalid_grant', 'The pre-authorized code is not valid');
    if (offer.txCodeHash && !matchesHash(body.tx_code || '', offer.txCodeHash)) {
      // A few wrong transaction codes end the offer, so the code can't be guessed.
      offer.txFailures = (offer.txFailures || 0) + 1;
      if (offer.txFailures >= MAX_TX_FAILURES) {
        offer.status = 'expired';
        await sessions.del(codeKey);
        recordOffer(offer);
      }
      await sessions.set(`o:${offer.id}`, offer, settings.offerTtlSeconds + 86400);
      return oauthError(400, 'invalid_grant', 'The transaction code is not correct');
    }
    // The code is used once.
    if (!(await sessions.take(codeKey))) return oauthError(400, 'invalid_grant', 'The pre-authorized code is not valid');
    const accessToken = randomToken(32);
    await sessions.set(`t:${accessToken}`, { offerId: offer.id, ...(dpop && { jkt: dpop.thumbprint }) }, TOKEN_SECONDS);
    return json(200, {
      access_token: accessToken,
      token_type: dpop ? 'DPoP' : 'Bearer',
      expires_in: TOKEN_SECONDS,
      authorization_details: [{ type: 'openid_credential', credential_configuration_id: offer.typeId, credential_identifiers: [offer.typeId] }],
    });
  };

  const nonce = async () => {
    const value = randomToken(24);
    await sessions.set(`n:${value}`, true, NONCE_SECONDS);
    return json(200, { c_nonce: value });
  };

  const verifyProof = (jwt, base, algs) => {
    const decoded = decodeJws(jwt, 'invalid_proof');
    const { header, payload } = decoded;
    if (header.typ !== PROOF_TYP) throw new WalletError('invalid_proof', `The proof type header must be ${PROOF_TYP}`);
    if (!header.jwk || header.jwk.d) throw new WalletError('invalid_proof', 'The proof must carry the holder public key (jwk)');
    let key;
    try {
      key = toKeyObject(header.jwk, 'public');
    } catch {
      throw new WalletError('invalid_proof', 'The holder key cannot be read');
    }
    if (!verifySignature(decoded, key, algs)) throw new WalletError('invalid_proof', 'The proof signature does not match');
    if (payload.aud !== base) throw new WalletError('invalid_proof', 'The proof is not for this issuer (aud)');
    const now = Math.floor(Date.now() / 1000);
    if (!(Math.abs(now - Number(payload.iat)) <= PROOF_MAX_AGE_SECONDS)) throw new WalletError('invalid_proof', 'The proof is not fresh');
    const { d, ...publicJwk } = header.jwk;
    return { jwk: publicJwk, nonce: payload.nonce };
  };

  const fetchClaims = async (offer, type) => {
    if (offer.claims) return offer.claims;
    let answer;
    try {
      answer = await provider.post(wallet.provider, wallet.provider.claimsUrl, { event: 'claims.requested', offerId: offer.id, subject: offer.subject, credentialType: type.id });
    } catch {
      throw new WalletError('provider_unavailable', 'The provider server could not be reached', 503);
    }
    if (answer.status !== 200 || !answer.json?.claims || typeof answer.json.claims !== 'object') {
      throw new WalletError('provider_unavailable', `The provider server did not return the claims (it answered ${answer.status})`, 503);
    }
    const missing = type.claims.filter((claim) => claim.required !== false && answer.json.claims[claim.path[0]] === undefined);
    if (missing.length) throw new WalletError('provider_unavailable', `The provider server left out required claims: ${missing.map((claim) => claim.path.join('.')).join(', ')}`, 503);
    const known = new Set(type.claims.map((claim) => claim.path[0]));
    return Object.fromEntries(Object.entries(answer.json.claims).filter(([name]) => known.has(name)));
  };

  const credential = async (ctx, base) => {
    const header = String(ctx.headers.authorization || '');
    const match = header.match(/^(Bearer|DPoP)\s+(.+)$/i);
    if (!match) return oauthError(401, 'invalid_token', 'Send the access token from the token endpoint', { 'www-authenticate': 'Bearer' });
    const grant = await sessions.take(`t:${match[2]}`);
    if (!grant) return oauthError(401, 'invalid_token', 'The access token is not valid or was already used', { 'www-authenticate': 'Bearer error="invalid_token"' });
    if (grant.jkt) {
      try {
        const dpop = checkDpop(ctx.headers.dpop, { method: 'POST', url: `${base}/credential`, accessToken: match[2], algs: wallet.algs });
        if (dpop.thumbprint !== grant.jkt) throw new WalletError('invalid_dpop_proof', 'The DPoP key is not the one the token is bound to');
      } catch (error) {
        if (error instanceof WalletError) return oauthError(401, 'invalid_dpop_proof', error.message);
        throw error;
      }
    }
    const offer = await loadOffer(grant.offerId);
    if (!offer || offer.status !== 'pending') return oauthError(400, 'invalid_credential_request', 'The offer is no longer available');
    const type = wallet.types.get(offer.typeId);
    let body;
    try {
      body = parseBody(ctx);
    } catch (error) {
      return oauthError(400, 'invalid_credential_request', error.message);
    }
    const requested = body.credential_configuration_id || body.credential_identifier || offer.typeId;
    if (requested !== offer.typeId) return oauthError(400, 'unknown_credential_configuration', 'The offer is for another credential');
    const jwts = Array.isArray(body.proofs?.jwt) ? body.proofs.jwt : body.proof?.jwt ? [body.proof.jwt] : [];
    if (!jwts.length) return oauthError(400, 'invalid_proof', 'Send a proof of possession of the holder key (proofs.jwt)');
    if (jwts.length > settings.batchSize) return oauthError(400, 'invalid_proof', `At most ${settings.batchSize} proofs per request`);

    let holders;
    try {
      holders = jwts.map((jwt) => verifyProof(jwt, base, wallet.algs));
    } catch (error) {
      if (error instanceof WalletError) return oauthError(400, 'invalid_proof', error.message);
      throw error;
    }
    const nonces = [...new Set(holders.map((holder) => holder.nonce))];
    if (nonces.length !== 1 || !nonces[0] || !(await sessions.take(`n:${nonces[0]}`))) {
      return oauthError(400, 'invalid_nonce', 'Get a fresh c_nonce from the nonce endpoint and sign it in the proof');
    }

    let claims;
    try {
      claims = await fetchClaims(offer, type);
    } catch (error) {
      if (error instanceof WalletError) return json(error.status, { error: 'credential_request_denied', error_description: error.message });
      throw error;
    }

    const now = Date.now();
    const iat = Math.floor(now / 1000);
    const exp = iat + type.validityDays * 86400;
    const issued = [];
    for (const holder of holders) {
      const index = await statusAllocator.next();
      const id = `${issuer.listId}-${index}`;
      const sdJwt = issueSdJwt({
        privateKey: issuer.key,
        alg: issuer.alg,
        x5c: issuer.x5c,
        iss: base,
        vct: type.vcts[0],
        claims,
        holderJwk: holder.jwk,
        status: { status_list: { idx: index, uri: `${base}/status/${issuer.listId}` } },
        iat,
        nbf: iat,
        exp,
      });
      issued.push({ id, index, credential: sdJwt });
    }
    offer.status = 'redeemed';
    offer.redeemedAt = new Date(now).toISOString();
    offer.credentialIds = issued.map((item) => item.id);
    offer.claims = null;
    await sessions.set(`o:${offer.id}`, offer, 86400);
    recordOffer(offer);
    for (const item of issued) {
      events.push({
        type: 'issued', id: item.id, offerId: offer.id, clientId: offer.clientId, credentialType: type.id, subject: offer.subject,
        listId: issuer.listId, statusIndex: item.index, node: statusAllocator.nodeName,
        issuedAt: new Date(iat * 1000).toISOString(), expiresAt: new Date(exp * 1000).toISOString(), claimNames: Object.keys(claims),
      });
    }
    provider.deliver(wallet.provider, {
      event: 'credential.issued', id: offer.id, subject: offer.subject, credentialType: type.id, credentialIds: offer.credentialIds,
    });
    return json(200, { credentials: issued.map((item) => ({ credential: item.credential })) });
  };

  const parseCredentialId = (id) => {
    const match = String(id).match(/^([A-Za-z0-9_-]{1,40})-(\d{1,9})$/);
    if (!match || match[1] !== issuer.listId) return null;
    const index = Number(match[2]);
    return index < issuer.listSize ? index : null;
  };

  const changeStatus = async (ctx, id, action) => {
    const value = { revoke: STATUS.revoked, suspend: STATUS.suspended, reinstate: STATUS.valid }[action];
    if (value === undefined) return json(404, { error: 'not_found', message: 'Use revoke, suspend or reinstate' });
    const index = parseCredentialId(id);
    if (index === null) return json(404, { error: 'not_found', message: 'No such credential' });
    const current = overlay.has(index) ? overlay.get(index) : issuer.entries.get(index) || STATUS.valid;
    if (current === STATUS.revoked && value !== STATUS.revoked) return json(409, { error: 'conflict', message: 'A revoked credential stays revoked' });
    overlay.set(index, value);
    statusCache = null;
    events.push({ type: 'credentialStatus', id, listId: issuer.listId, statusIndex: index, status: Object.keys(STATUS).find((name) => STATUS[name] === value), clientId: ctx.clientId });
    return json(200, { id, status: Object.keys(STATUS).find((name) => STATUS[name] === value) });
  };

  const statusList = (listId, base) => {
    if (listId !== issuer.listId) return json(404, { error: 'not_found', message: 'No such status list' });
    if (!statusCache || statusCache.until < Date.now()) {
      const entries = new Map(issuer.entries);
      for (const [index, value] of overlay) entries.set(index, value);
      const token = signStatusList({
        uri: `${base}/status/${listId}`, size: issuer.listSize, bits: 2, entries, privateKey: issuer.key, alg: issuer.alg, x5c: issuer.x5c,
      });
      statusCache = { token, until: Date.now() + STATUS_CACHE_MS };
    }
    return { status: 200, headers: { 'content-type': 'application/statuslist+jwt', 'cache-control': 'max-age=30' }, body: Buffer.from(statusCache.token) };
  };

  const handle = async (ctx, base) => {
    const route = `${ctx.method} ${ctx.operationPath}`;
    switch (route) {
      case 'POST /offers': return createOffer(ctx, base);
      case 'GET /offers/{id}': return getOffer(ctx, ctx.params.id);
      case 'POST /credentials/{id}/{action}': return changeStatus(ctx, ctx.params.id, ctx.params.action);
      case 'GET /.well-known/openid-credential-issuer': return metadata(base);
      case 'GET /.well-known/oauth-authorization-server': return authorizationServer(base);
      case 'GET /credential-offer/{id}': return credentialOffer(ctx.params.id, base);
      case 'POST /token': return token(ctx, base);
      case 'POST /nonce': return nonce();
      case 'POST /credential': return credential(ctx, base);
      case 'GET /status/{listId}': return statusList(ctx.params.listId, base);
      default: return json(404, { error: 'not_found', message: 'This operation is not part of the issuance API' });
    }
  };

  // The console's configuration now carries these entries: forget the local copies.
  const configure = () => {
    for (const [index, value] of overlay) if (issuer.entries.get(index) === value || (value === STATUS.valid && !issuer.entries.has(index))) overlay.delete(index);
    statusCache = null;
  };

  return { handle, metadata, authorizationServer, configure };
};

module.exports = { createIssuer, PRE_AUTHORIZED, PROOF_TYP, jwkThumbprint };
