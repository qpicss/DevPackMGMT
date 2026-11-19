// The built-in APIs of wallet gateways, as OpenAPI 3.0 documents. The console adds them to a
// catalog (Set up on the gateway's Wallet page), so they are sold through products and
// subscriptions like any API. The gateway answers them itself (gateway/src/wallet), not a backend.
// `info.x-wallet-builtin` marks them; wallet endpoints are public (x-gateway-access: public), the
// provider server's endpoints need a token and an approved subscription.

const BUILTIN_MARK = 'x-wallet-builtin';
const BUILTINS = {
  'wallet-verifier': { name: 'Credential verification', basePath: '/wallet/verify' },
  'wallet-issuer': { name: 'Credential issuance', basePath: '/wallet/issue' },
};
const KIND_BUILTIN = { 'wallet-verifier': 'wallet-verifier', 'wallet-issuer': 'wallet-issuer' };

const json = (schema) => ({ content: { 'application/json': { schema } } });
const error = { description: 'Error', ...json({ type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } }) };
const publicOp = (operation) => ({ ...operation, 'x-gateway-access': 'public' });

const verifierSpec = () => ({
  openapi: '3.0.3',
  info: {
    title: BUILTINS['wallet-verifier'].name,
    version: '1.0.0',
    description: 'Verifies EU Digital Identity Wallet credentials (OpenID4VP, SD-JWT VC). Your provider server starts a verification and receives the verified claims; the gateway talks to the wallet.',
    [BUILTIN_MARK]: 'wallet-verifier',
  },
  paths: {
    '/verifications': {
      post: {
        operationId: 'startVerification',
        summary: 'Start a verification',
        requestBody: {
          required: true,
          ...json({
            type: 'object',
            required: ['credentialType'],
            properties: {
              credentialType: { type: 'string', description: 'A credential type configured on the gateway' },
              claims: { type: 'array', items: { type: 'string' }, description: 'Claim names or dotted paths; all of the type by default' },
              redirectUri: { type: 'string', description: 'Where the wallet sends the person afterwards (same-device flow)' },
              reference: { type: 'string', description: 'Your own reference, echoed in the callback' },
            },
          }),
        },
        responses: { 201: { description: 'Started: show deep_link as a QR code or a link' }, 400: error, 403: error },
      },
    },
    '/verifications/{id}': {
      get: {
        operationId: 'getVerification',
        summary: 'Status of a verification (claims until they are delivered to your callback)',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { 200: { description: 'Status' }, 404: error },
      },
    },
    '/request/{id}': {
      get: publicOp({ operationId: 'getRequestObject', summary: 'Wallet: the signed request object', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'application/oauth-authz-req+jwt' }, 410: error } }),
      post: publicOp({ operationId: 'postRequestObject', summary: 'Wallet: the signed request object (request_uri_method post)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'application/oauth-authz-req+jwt' }, 410: error } }),
    },
    '/response/{id}': {
      post: publicOp({ operationId: 'postResponse', summary: 'Wallet: the authorization response (direct_post.jwt)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Accepted' }, 400: error } }),
    },
  },
});

const issuerSpec = () => {
  const idParam = [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }];
  return {
    openapi: '3.0.3',
    info: {
      title: BUILTINS['wallet-issuer'].name,
      version: '1.0.0',
      description: 'Issues your attestations into EU Digital Identity Wallets (OpenID4VCI pre-authorized code flow, SD-JWT VC). Your provider server creates offers and supplies the claims; the gateway signs the credentials with your issuer key.',
      [BUILTIN_MARK]: 'wallet-issuer',
    },
    paths: {
      '/offers': {
        post: {
          operationId: 'createOffer',
          summary: 'Create a credential offer',
          requestBody: {
            required: true,
            ...json({
              type: 'object',
              required: ['credentialType', 'subject'],
              properties: {
                credentialType: { type: 'string' },
                subject: { type: 'string', description: 'Your reference for the person; sent back when the gateway asks for the claims' },
                claims: { type: 'object', description: 'The claims now, instead of fetching them from your claims URL at redemption' },
                txCode: { type: 'boolean', description: 'Ask the person for a 6-digit transaction code (returned once as tx_code)' },
              },
            }),
          },
          responses: { 201: { description: 'Offer created: show deep_link as a QR code or a link' }, 400: error },
        },
      },
      '/offers/{id}': { get: { operationId: 'getOffer', summary: 'Status of an offer', parameters: idParam, responses: { 200: { description: 'pending, redeemed or expired' }, 404: error } } },
      '/credentials/{id}/{action}': {
        post: {
          operationId: 'changeCredentialStatus',
          summary: 'Revoke, suspend or reinstate an issued credential',
          parameters: [...idParam, { name: 'action', in: 'path', required: true, schema: { type: 'string', enum: ['revoke', 'suspend', 'reinstate'] } }],
          responses: { 200: { description: 'Changed' }, 404: error, 409: error },
        },
      },
      '/.well-known/openid-credential-issuer': { get: publicOp({ operationId: 'issuerMetadata', summary: 'Wallet: Credential Issuer metadata (also served at /.well-known/openid-credential-issuer{base path})', responses: { 200: { description: 'Metadata' } } }) },
      '/.well-known/oauth-authorization-server': { get: publicOp({ operationId: 'authorizationServerMetadata', summary: 'Wallet: authorization server metadata', responses: { 200: { description: 'Metadata' } } }) },
      '/credential-offer/{id}': { get: publicOp({ operationId: 'credentialOffer', summary: 'Wallet: the credential offer', parameters: idParam, responses: { 200: { description: 'Offer' }, 404: error } }) },
      '/token': { post: publicOp({ operationId: 'token', summary: 'Wallet: pre-authorized code -> access token', responses: { 200: { description: 'Token' }, 400: error } }) },
      '/nonce': { post: publicOp({ operationId: 'nonce', summary: 'Wallet: a fresh c_nonce', responses: { 200: { description: 'Nonce' } } }) },
      '/credential': { post: publicOp({ operationId: 'credential', summary: 'Wallet: issue the credential', responses: { 200: { description: 'Credentials' }, 400: error, 401: error } }) },
      '/status/{listId}': { get: publicOp({ operationId: 'statusList', summary: 'The Token Status List of your credentials', parameters: [{ name: 'listId', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'application/statuslist+jwt' } } }) },
    },
  };
};

const builtinSpec = (builtin) => (builtin === 'wallet-verifier' ? verifierSpec() : builtin === 'wallet-issuer' ? issuerSpec() : null);
const builtinOf = (spec) => {
  const value = spec?.info?.[BUILTIN_MARK];
  return BUILTINS[value] ? value : null;
};

module.exports = { BUILTINS, BUILTIN_MARK, KIND_BUILTIN, builtinSpec, builtinOf };
