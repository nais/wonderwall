# DPoP

Wonderwall supports [OAuth 2.0 Demonstrating Proof of Possession (DPoP, RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449) for identity-provider token requests and proxied upstream requests.

## Requirements

To use DPoP, all of the following must be true:

- The runtime mode is either the standalone or the SSO server mode.
- The client is configured with a client JWK through the `openid.client-jwk` setting or equivalent environment variable.
- The identity provider has the property `dpop_signing_alg_values_supported`  in the metadata document that supports the algorithm of the configured client JWK.

## Identity Provider

Wonderwall automatically uses DPoP against an identity provider when the requirements above are met.

When eligible to use DPoP, Wonderwall:

- Adds `dpop_jkt` to authorization requests, including pushed authorization requests.
- Adds DPoP proofs to all token requests for the `authorization_code` and `refresh_token` grant types.
- Retries token requests once when the identity provider returns a `use_dpop_nonce` challenge.
- Caches a returned `DPoP-Nonce` in memory for later token requests until a new one is returned.

Wonderwall accepts the token type returned by the identity provider. A `DPoP` response creates a DPoP-bound session.
A `Bearer` response creates a Bearer session.

If provider discovery does not advertise a compatible algorithm, Wonderwall uses the existing Bearer flow.

## Session Binding

Wonderwall stores the public-key thumbprint in each DPoP-bound session.
This supports opaque access tokens and records which key the identity provider bound to the session.

Wonderwall validates the stored thumbprint whenever it loads the session.
It invalidates the session when:

- The configured client key changes.
- Provider discovery no longer advertises a compatible DPoP algorithm.

All replicas that share sessions must use the same client JWK.

## Upstream Presentation

The [`upstream.dpop`](configuration.md) setting controls how Wonderwall presents a DPoP-bound access token to the upstream resource server.
It defaults to `false`.

All [requirements](#requirements) must be met before `upstream.dpop` can be set to `true`.
Wonderwall will reject the configuration at startup if any requirement is not met.

When `upstream.dpop` is `false`, Wonderwall sends:

```http
Authorization: Bearer <access-token>
```

When `upstream.dpop` is `true`, Wonderwall sends:

```http
Authorization: DPoP <access-token>
DPoP: <proof>
```

Each proof has a fresh `jti` and includes:

- `ath`, derived from the access token.
- `htm`, derived from the request method.
- `htu`, derived from the public ingress URL.

The resource server must validate `htu` against the public ingress URL, not Wonderwall's internal connection to the upstream.

The setting does not affect Bearer sessions.
See [HTTP Request Headers](architecture.md#http-request-headers) for the complete header behaviour.

### Upstream Nonces

When the upstream resource server returns `DPoP-Nonce`, Wonderwall caches
the value in memory and includes it in subsequent DPoP proofs.
Nonces are not shared between multiple replicas.

Wonderwall does not retry the request that received the nonce. A new nonce
replaces the cached value.

Responses to caller-supplied DPoP requests do not update Wonderwall's cache.

## Runtime Modes

| Runtime mode | Identity-provider DPoP                                    | Upstream DPoP                                                                                    |
|--------------|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Standalone   | Automatic when the [requirements](#requirements) are met. | Optional with `upstream.dpop=true`.                                                              |
| SSO server   | Automatic when the [requirements](#requirements) are met. | Optional with `upstream.dpop=true`.                                                              |
| SSO proxy    | Not applicable. The proxy does not perform the OIDC flow. | Not supported. The proxy does not have a client key and rejects `upstream.dpop=true` at startup. |
