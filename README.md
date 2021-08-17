# wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

`wonderwall` is an application that implements OpenID Connect in a way that makes it easy to plug into Kubernetes as a sidecar.
As such, this is OIDC as a sidecar, or OaaS, or to explain the joke: Oasis - Wonderwall

Currently, the scope is to implement [ID-porten's preferred setup](https://docs.digdir.no/oidc_guide_idporten.html),

- user logins
- token exchange
- session handling
- front-channel logouts
- ... probably some other stuff 

once the user has a nice and valid token, `wonderwall` can redirect to the main container in the Kubernetes Pod, and the fun can commence.
