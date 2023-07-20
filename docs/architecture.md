# Architecture

The diagram below shows the overall architecture of an application when using Wonderwall as a sidecar in Kubernetes:

```mermaid
flowchart TB
    accTitle: System Architecture
    accDescr: The architectural diagram shows the browser sending a request into the Kubernetes container, requesting the ingress https://&ltapp&gt.nav.no, requesting the service https://&ltapp&gt.&ltnamespace&gt, sending it to the pod, which contains the sidecar. The sidecar sends a proxy request to the app, in addition to triggering and handling the Open ID Connect Auth Code Flow to the identity provider. The identity provider is outside the Kubernetes environment.

    idp(Identity Provider)
    Browser -- 1. initial request --> k8s
    Browser -- 2. redirected by Wonderwall --> idp
    idp -- 3. performs OpenID Connect Auth Code flow --> Browser

    subgraph k8s [Kubernetes]
        direction LR
        Ingress(Ingress<br>https://&ltapp&gt.nav.no) --> Service(Service<br>http://&ltapp&gt.&ltnamespace&gt) --> Wonderwall
        subgraph Pod
            direction TB
            Wonderwall -- 4. proxy request with access token --> Application
            Application -- 5. return response --> Wonderwall
        end
    end
```

Note that we do not provide any mechanisms to configure `Services` or inject the sidecar into `Deployments` at this time; this is left as an exercise for the reader.

The sequence diagram below shows the default behavior of Wonderwall:

```mermaid
sequenceDiagram
    accTitle: Sequence Diagram
    accDescr: The sequence diagram shows the default behaviour of the sidecar, depending on whether the user already has a session or not. If the user does have a session, the sequence is as follows: 1. The user visits a path, that requests the ingress.  2. The request is forwarded to wonderwall 3. Wonderwall checks for a session in session storage. 4. Wonderwall attaches Authorization header and proxies request and sends it to the application. 5. The application returns a response to Wonderwall. 6. Wonderwall returns the response to the user. If the user does not have a session, the sequence is as follows: 1. The user visits a path, that requests the ingress.  2. The request is forwarded to wonderwall 3. Wonderwall checks for a session in session storage. 4. Wonderwall proxies the request as-is and sends it to the application. 5. The application returns a response to Wonderwall. 6. Wonderwall returns the response to the user.

    actor User
    User->>Ingress: visits /path
    Ingress-->>Wonderwall: forwards request
    activate Wonderwall
    Wonderwall-->>Session Storage: checks for session
    alt has session
        Session Storage-->>Wonderwall: session found
        activate Wonderwall
        Wonderwall-->>Application: attaches Authorization header and proxies request
        Application-->>Wonderwall: returns response
        Wonderwall->>User: returns response
        deactivate Wonderwall
    else does not have session
        Session Storage-->>Wonderwall: no session found
        activate Wonderwall
        Wonderwall-->>Application: proxies request as-is
        Application-->>Wonderwall: returns response
        Wonderwall->>User: returns response
        deactivate Wonderwall
    end
```

# Modes

Wonderwall has two runtime modes, the choice of which depends on your specific setup:

1. The _Standalone mode_ is the default mode and is the most restrictive.
2. The _Single Sign-On (SSO) mode_ is an optional mode where the restrictions are loosened.

## Standalone Mode (Default)

The standalone mode is the default mode for Wonderwall and the most restrictive mode.
It encourages a 1-to-1 mapping for a single identity provider client to a upstream application, where each application has their own identity provider client (i.e. their own set of credentials, their own set of redirect URLs, etc.)

This mode is suitable for organizations seeking to implement zero-trust based token architectures, but requires some maturity in terms of automated provisioning and configuration of identity provider clients.

Restrictions:

- Cookies are set to the match the most specific domain and path (if any) for the configured `ingress`.
- Allowed redirects are also similarly restricted to the same domain and path.
- Users will have separate sessions for each application.
  - If using an identity provider with SSO capabilities, this means that the user will see a "redirect blip" when navigating between applications. This may be undesirable in terms of user experience, which is an unfortunate trade-off for increased security.
  - If you want sessions to be seamlessly shared between applications on a common domain, use Wonderwall in [SSO mode](#single-sign-on-sso-mode).

Generally speaking, the recommended approach when using Wonderwall in standalone mode is to put it in front of your backend-for-frontend server that serves your frontend.
Requests to other APIs should be done through the backend-for-frontend by reverse-proxying.
This avoids having to configure CORS as well as the restrictions on cookies and allowed redirects mandated by Wonderwall.

See the [configuration](configuration.md#standalone-mode-default) document for configuring the standalone mode.

## Single Sign-On (SSO) Mode

The single sign-on mode is an optional mode where some restrictions are loosened, compared to the standalone mode.

The most notable changes are:

- Session cookies are now set and accessible for the whole SSO (sub-)domain that is configured.
- The [`/oauth2/session`](endpoints.md#oauth2session) and [`/oauth2/session/refresh`](endpoints.md#oauth2sessionrefresh) endpoints are configured to allow CORS from origins matching the SSO (sub-)domain.
- [Automatic token refreshes are unavailable](sessions.md#automatic-vs-manual-refresh).

The SSO mode is mostly just the standalone mode split into two parts; a server part and a proxy part.

It allows a single identity provider client to be used across multiple upstream applications within the same domain.
While you technically can do the same using the standalone mode, that approach has multiple issues:

- Having to distribute and synchronize the private JWK to all deployments.
- Having to manage and register each relying party's callback URL at the identity provider. Some providers also impose a limit for each client.

Using the SSO mode only requires you to register the callback URLs that belong to the SSO server.
The server is also the only part that needs to access the private JWK; the SSO proxies will work without it.

The diagram below shows the overall architecture when deploying Wonderwall in SSO mode:

```mermaid
flowchart BT
    accTitle: System Architecture (SSO Mode)
    accDescr: The architectural diagram shows the browser sending a request into the Kubernetes container, requesting the ingress https://&ltapp&gt.nav.no, requesting the service https://&ltapp&gt.&ltnamespace&gt, sending it to the pod, which contains the sidecar. The sidecar sends a proxy request to the app, in addition to triggering and handling the Open ID Connect Auth Code Flow to the identity provider. The identity provider is outside the Kubernetes environment.

    Browser["Browser (User Agent)"]
    idp["Identity Provider"]

    Ingress["Application Ingress<br>https://&ltapp&gt.nav.no"]
    Service["Application Service<br>http://&ltapp&gt.&ltnamespace&gt"]
    Wonderwall["Wonderwall SSO Proxy"]

    IngressSSO["Ingress<br>https://sso.nav.no"]
    ServiceSSO["Service<br>http://wonderwall-sso-server.&ltnamespace&gt"]
    WonderwallSSO["Wonderwall SSO Server"]

    Browser -- 1. initial request --> Application
    Application -- 2. redirected by Wonderwall SSO Proxy --> ApplicationSSO
    ApplicationSSO -- 3. redirected by Wonderwall SSO Server --> idp
    idp -- 4. performs OpenID Connect Auth Code flow <--> Browser
    idp -- 5. redirect to callback after successful login --> ApplicationSSO
    ApplicationSSO -- 6. redirect after successful callback --> Application
    Application -- 8. return response --> Browser

    subgraph ApplicationSSO["Wonderwall SSO Server"]
        direction TB
        IngressSSO <--> ServiceSSO <--> WonderwallSSO
    end

    subgraph Application["Application with SSO Proxy"]
        direction TB
        Ingress <--> Service <--> Wonderwall
        subgraph Pod
            Wonderwall -- 7. proxy request with access token <--> ApplicationContainer["Application Container"]
        end
    end
```

See the [configuration](configuration.md#single-sign-on-sso-mode) document for enabling and configuring the SSO mode.

### SSO Server

The SSO server effectively has the same functionality as the standalone mode and handles the same endpoints, just without the reverse-proxying to an upstream application.

The [`/oauth2/login`](endpoints.md#oauth2login) and the [`/oauth2/logout`](endpoints.md#oauth2logout) endpoints now accept redirect URLs matching any subdomain and path within the configured SSO (sub-)domain.

The SSO server should be deployed separately as its own application, being a central relying party for all proxies that should share the same sessions.

### SSO Proxy

The SSO proxy is effectively a read-only replica version of the standalone mode, providing the reverse-proxy functionality to the upstream application.

All OpenID Connect functionality is delegated to the SSO server by means of reverse-proxying or redirects, which is completely transparent to applications.
This also means that all endpoints are still handled as before.

Applications may thus choose to use either the SSO server or the SSO proxy endpoints, whichever is more convenient.
Bear in mind that the SSO proxy restricts allowed redirects to only relative URLs, as opposed to the SSO server.

The SSO proxy should be deployed as a sidecar, just like the standalone mode for Wonderwall.
