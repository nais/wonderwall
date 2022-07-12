package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

type IdentityProvider struct {
	cancelFunc          context.CancelFunc
	Cfg                 *config.Config
	OpenIDConfig        Configuration
	Provider            TestProvider
	ProviderHandler     *IdentityProviderHandler
	ProviderServer      *httptest.Server
	RelyingPartyHandler *router.Handler
	RelyingPartyServer  *httptest.Server
}

func (in IdentityProvider) Close() {
	in.cancelFunc()
	in.ProviderServer.Close()
	in.RelyingPartyServer.Close()
}

func (in IdentityProvider) RelyingPartyClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	client := in.RelyingPartyServer.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client
}

func NewIdentityProvider(cfg *config.Config) IdentityProvider {
	openidConfig := NewTestConfiguration(cfg)
	provider := newTestProvider(openidConfig)
	handler := newIdentityProviderHandler(provider, openidConfig)
	idpRouter := identityProviderRouter(handler)
	server := httptest.NewServer(idpRouter)

	openidConfig.Provider().Issuer = server.URL
	openidConfig.Provider().JwksURI = server.URL + "/jwks"
	openidConfig.Provider().AuthorizationEndpoint = server.URL + "/authorize"
	openidConfig.Provider().TokenEndpoint = server.URL + "/token"
	openidConfig.Provider().EndSessionEndpoint = server.URL + "/endsession"

	crypter := crypto.NewCrypter([]byte(cfg.EncryptionKey))
	sessionStore := session.NewMemory()

	ctx, cancel := context.WithCancel(context.Background())
	rpHandler, err := router.NewHandler(ctx, openidConfig, crypter, zerolog.Nop(), sessionStore)
	if err != nil {
		panic(err)
	}

	rpHandler.CookieOptions = rpHandler.CookieOptions.WithSecure(false)
	rpServer := httptest.NewServer(router.New(rpHandler))

	return IdentityProvider{
		cancelFunc:          cancel,
		Cfg:                 cfg,
		RelyingPartyHandler: rpHandler,
		RelyingPartyServer:  rpServer,
		OpenIDConfig:        openidConfig,
		Provider:            provider,
		ProviderHandler:     handler,
		ProviderServer:      server,
	}
}

func identityProviderRouter(ip *IdentityProviderHandler) chi.Router {
	r := chi.NewRouter()
	r.Get("/authorize", ip.Authorize)
	r.Post("/token", ip.Token)
	r.Get("/jwks", ip.Jwks)
	r.Get("/endsession", ip.EndSession)
	return r
}

type IdentityProviderHandler struct {
	Codes    map[string]AuthorizeRequest
	Config   openidconfig.Config
	Provider TestProvider
	Sessions map[string]string
}

func newIdentityProviderHandler(provider TestProvider, cfg openidconfig.Config) *IdentityProviderHandler {
	return &IdentityProviderHandler{
		Codes:    make(map[string]AuthorizeRequest),
		Config:   cfg,
		Provider: provider,
		Sessions: make(map[string]string),
	}
}

type AuthorizeRequest struct {
	AcrLevel      string
	CodeChallenge string
	Locale        string
	Nonce         string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func (ip *IdentityProviderHandler) signToken(token jwt.Token) (string, error) {
	privateJwkSet := *ip.Provider.PrivateJwkSet()
	signer, ok := privateJwkSet.Key(0)
	if !ok {
		return "", fmt.Errorf("could not get signer")
	}

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signer))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}

func (ip *IdentityProviderHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state := query.Get("state")
	redirect := query.Get("redirect_uri")
	acrLevel := query.Get("acr_values")
	codeChallenge := query.Get("code_challenge")
	locale := query.Get("ui_locales")
	nonce := query.Get("nonce")

	if state == "" || redirect == "" || acrLevel == "" || codeChallenge == "" || locale == "" || nonce == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing required fields"))
		return
	}

	code := uuid.New().String()
	ip.Codes[code] = AuthorizeRequest{
		AcrLevel:      acrLevel,
		CodeChallenge: codeChallenge,
		Locale:        locale,
		Nonce:         nonce,
	}

	u, err := url.Parse(redirect)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("couldn't parse redirect uri"))
		return
	}
	v := url.Values{}
	v.Set("code", code)
	v.Set("state", state)
	if ip.Provider.GetOpenIDConfiguration().SessionStateRequired() {
		sessionID := uuid.New().String()
		v.Set("session_state", sessionID)
	}

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (ip *IdentityProviderHandler) Jwks(w http.ResponseWriter, r *http.Request) {
	jwks, _ := ip.Provider.GetPublicJwkSet(r.Context())
	json.NewEncoder(w).Encode(jwks)
}

func (ip *IdentityProviderHandler) Token(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("malformed payload?"))
		return
	}

	code := r.PostForm.Get("code")

	if len(code) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing code"))
		return
	}

	auth, ok := ip.Codes[code]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("no matching code"))
		return
	}

	expires := int64(1200)

	sub := uuid.New().String()

	clientID := r.PostForm.Get("client_id")
	if len(clientID) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing client_id"))
		return
	}

	clientAssertion := r.PostForm.Get("client_assertion")
	if len(clientID) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing client_assertion"))
		return
	}

	clientJwk := ip.Config.Client().GetClientJWK()
	clientJwkSet := jwk.NewSet()
	clientJwkSet.AddKey(clientJwk)
	publicClientJwkSet, err := jwk.PublicSetOf(clientJwkSet)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to create public client jwk set"))
		return
	}

	opts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithKeySet(publicClientJwkSet),
		jwt.WithIssuer(ip.Config.Client().GetClientID()),
		jwt.WithSubject(ip.Config.Client().GetClientID()),
		jwt.WithClaimValue("scope", ip.Config.Client().GetScopes().String()),
		jwt.WithAudience(ip.Provider.GetOpenIDConfiguration().Issuer),
	}
	_, err = jwt.Parse([]byte(clientAssertion), opts...)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		v := url.Values{}
		v.Set("error", "Unauthenticated")
		v.Set("error_description", "invalid client assertion")
		v.Encode()
		w.Write([]byte(fmt.Sprintf(v.Encode()+"%+v", err)))
		return
	}

	accessToken := jwt.New()
	accessToken.Set("sub", sub)
	accessToken.Set("iss", ip.Provider.GetOpenIDConfiguration().Issuer)
	accessToken.Set("acr", auth.AcrLevel)
	accessToken.Set("iat", time.Now().Unix())
	accessToken.Set("exp", time.Now().Unix()+expires)
	signedAccessToken, err := ip.signToken(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	sessionID := uuid.New().String()
	ip.Sessions[sessionID] = clientID

	idToken := jwt.New()
	idToken.Set("sub", sub)
	idToken.Set("iss", ip.Provider.GetOpenIDConfiguration().Issuer)
	idToken.Set("aud", clientID)
	idToken.Set("locale", auth.Locale)
	idToken.Set("nonce", auth.Nonce)
	idToken.Set("acr", auth.AcrLevel)
	idToken.Set("iat", time.Now().Unix())
	idToken.Set("exp", time.Now().Unix()+expires)

	// If the sid claim should be in token and in active session
	if ip.Provider.OpenIDConfiguration.SidClaimRequired() {
		idToken.Set("sid", sessionID)
	}

	signedIdToken, err := ip.signToken(idToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	token := &tokenResponse{
		AccessToken:  signedAccessToken,
		TokenType:    "Bearer",
		IDToken:      signedIdToken,
		RefreshToken: code + "some-refresh-token",
		ExpiresIn:    expires,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *IdentityProviderHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	postLogoutRedirectURI := query.Get("post_logout_redirect_uri")

	if postLogoutRedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing required parameters"))
		return
	}

	u, err := url.Parse(postLogoutRedirectURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("couldn't parse post_logout_redirect_uri"))
		return
	}

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}
