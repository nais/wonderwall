# DPoP

Wonderwall supports [OAuth 2.0 Demonstrating Proof of Possession (DPoP, RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449) for identity-provider token requests and proxied upstream requests.

DPoP support is disabled by default.
It must be explicitly opted in to with the `openid.dpop` configuration flag or `WONDERWALL_OPENID_DPOP=true` environment variable.

## Requirements

To use DPoP, all the following must be true:

- `openid.dpop` is set to `true`.
- Wonderwall runs in standalone mode.
- The client is configured with a client JWK through the `openid.client-jwk` setting or equivalent environment variable.
- The identity provider advertises the client JWK's signing algorithm in `dpop_signing_alg_values_supported`.
- The upstream accepts `Authorization: DPoP <token>` and validates the accompanying `DPoP` proof and token binding, as specified by [RFC 9449 Section 7.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1).

Wonderwall validates the identity provider requirements at startup. The operator must verify upstream support because identity provider discovery does not describe resource server capabilities.

## Identity Provider

When `openid.dpop` is enabled, Wonderwall:

- Adds `dpop_jkt` to authorization requests, including pushed authorization requests.
- Adds DPoP proofs to all token requests for the `authorization_code` and `refresh_token` grant types.
- Retries token requests once when the identity provider returns a `use_dpop_nonce` challenge.
- Caches a returned `DPoP-Nonce` in memory for later token requests until a new one is returned.

The identity provider must return `token_type=DPoP`.
Wonderwall rejects Bearer responses because `openid.dpop=true` requires DPoP-bound access tokens throughout the flow.

When `openid.dpop` is disabled, Wonderwall does not send DPoP proofs to the identity provider and requires Bearer token responses.

## Session Binding

Wonderwall stores the public-key thumbprint in each DPoP-bound session.
This supports opaque access tokens and records which key the identity provider bound to the session.

Wonderwall validates the stored thumbprint whenever it loads the session.
It invalidates the session when:

- The configured client key changes.
- The configured DPoP mode no longer matches the session.

All replicas that share sessions must use the same client JWK.

## Upstream Requests

When `openid.dpop` is disabled, Wonderwall sends:

```http
Authorization: Bearer <access-token>
```

When `openid.dpop` is enabled, Wonderwall sends:

```http
Authorization: DPoP <access-token>
DPoP: <proof>
```

Each proof has a fresh `jti` and includes:

- `ath`, derived from the access token.
- `htm`, derived from the request method.
- `htu`, derived from the public ingress URL.

Wonderwall uses the public ingress URL for `htu`.
The upstream must use that external URL when validating the proof, even though its connection from Wonderwall uses HTTP.

See [HTTP Request Headers](architecture.md#http-request-headers) for the complete header behaviour.

### Upstream Nonces

When the upstream resource server returns `DPoP-Nonce`, Wonderwall caches
the value in memory and includes it in subsequent DPoP proofs.
Nonces are not shared between multiple replicas.

Wonderwall does not retry the request that received the nonce. A new nonce
replaces the cached value.

Responses to caller-supplied DPoP requests do not update Wonderwall's cache.

## Runtime Modes

| Runtime mode | DPoP support                                                             |
|--------------|--------------------------------------------------------------------------|
| Standalone   | Enabled end-to-end with `openid.dpop=true`.                              |
| SSO server   | Not supported. Application proxies do not hold the DPoP key.             |
| SSO proxy    | Not supported. The proxy cannot generate proofs without the private key. |
