package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	handlerpkg "github.com/nais/wonderwall/pkg/handler"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	scopespkg "github.com/nais/wonderwall/pkg/openid/scopes"
	"github.com/nais/wonderwall/pkg/router"
)

type IdentityProvider struct {
	Cfg                 *config.Config
	OpenIDConfig        *TestConfiguration
	ProviderHandler     *IdentityProviderHandler
	ProviderServer      *httptest.Server
	RelyingPartyHandler *handlerpkg.Standalone
	RelyingPartyServer  *httptest.Server
	redisServer         *miniredis.Miniredis
}

func (in *IdentityProvider) Close() {
	in.ProviderServer.Close()
	in.RelyingPartyServer.Close()
	in.redisServer.Close()
}

func (in *IdentityProvider) RelyingPartyClient() *http.Client {
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

func (in *IdentityProvider) GetRequest(target string) *http.Request {
	return NewGetRequest(target, in.RelyingPartyHandler.GetIngresses())
}

func NewIdentityProvider(cfg *config.Config) *IdentityProvider {
	rpServer := newRelyingPartyServer()
	cfg.Ingresses = append(cfg.Ingresses, rpServer.GetURL())

	openidConfig := NewTestConfiguration(cfg)
	jwksProvider := NewTestJwksProvider()
	handler := newIdentityProviderHandler(jwksProvider, openidConfig)
	idpRouter := identityProviderRouter(handler)
	server := httptest.NewServer(idpRouter)

	openidConfig.TestProvider.SetAuthorizationEndpoint(server.URL + "/authorize")
	openidConfig.TestProvider.SetEndSessionEndpoint(server.URL + "/endsession")
	openidConfig.TestProvider.SetIssuer(server.URL)
	openidConfig.TestProvider.SetJwksURI(server.URL + "/jwks")
	openidConfig.TestProvider.SetTokenEndpoint(server.URL + "/token")

	crypter := crypto.NewCrypter([]byte(cfg.EncryptionKey))

	rds, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	cfg.Redis.TLS = false
	cfg.Redis.Address = rds.Addr()

	rpHandler, err := handlerpkg.NewStandalone(cfg, jwksProvider, openidConfig, crypter)
	if err != nil {
		panic(err)
	}

	rpHandler.CookieOptions = cookie.DefaultOptions().WithSecure(false)

	rpRouter := router.New(rpHandler, cfg)
	rpServer.SetHandler(rpRouter)
	rpServer.Start()

	ip := &IdentityProvider{
		Cfg:                 cfg,
		RelyingPartyHandler: rpHandler,
		RelyingPartyServer:  rpServer.Server,
		OpenIDConfig:        openidConfig,
		ProviderHandler:     handler,
		ProviderServer:      server,
		redisServer:         rds,
	}

	return ip
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
	Codes         map[string]*AuthorizeRequest
	Config        openidconfig.Config
	Provider      *TestProvider
	Sessions      map[string]string
	RefreshTokens map[string]*RefreshTokenData
	TokenDuration time.Duration
}

func newIdentityProviderHandler(provider *TestProvider, cfg openidconfig.Config) *IdentityProviderHandler {
	return &IdentityProviderHandler{
		Codes:         make(map[string]*AuthorizeRequest),
		Config:        cfg,
		Provider:      provider,
		Sessions:      make(map[string]string),
		RefreshTokens: make(map[string]*RefreshTokenData),
		TokenDuration: time.Minute,
	}
}

type AuthorizeRequest struct {
	AcrLevel      string
	ClientID      string
	CodeChallenge string
	Locale        string
	Nonce         string
	RedirectUri   string
	SessionID     string
}

type RefreshTokenData struct {
	ClientID        string
	RefreshToken    string
	OriginalIDToken jwt.Token
	SessionID       string
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
	nonce := query.Get("nonce")
	responseMode := query.Get("response_mode")
	responseType := query.Get("response_type")
	clientId := query.Get("client_id")
	scope := query.Get("scope")

	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	acrLevel := query.Get("acr_values")
	locale := query.Get("ui_locales")

	required := map[string]string{
		"state":         state,
		"nonce":         nonce,
		"redirect":      redirect,
		"response_type": responseType,
		"response_mode": responseMode,
		"client_id":     clientId,
		"scope":         scope,

		// we enforce usage of PKCE
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
	}

	for param, value := range required {
		if len(value) <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("missing required field '%s'", param)))
			return
		}
	}

	invalidParamResponse := func(w http.ResponseWriter, param, actual string, expected []string) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("'%s' is an invalid value for '%s', must be '%s'", actual, param, expected)))
	}

	allowedParamValues := map[string][]string{
		"code_challenge_method": {"S256"},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"acr_values":            {"", "Level3", "Level4"},
		"ui_locales":            {"", "nb", "nn", "en", "se"},
	}

	for param, allowed := range allowedParamValues {
		paramValue := query.Get(param)

		found := false
		for _, allowedValue := range allowed {
			if paramValue == allowedValue {
				found = true
				break
			}
		}

		if !found {
			invalidParamResponse(w, param, paramValue, allowed)
			return
		}
	}

	scopes := strings.Split(scope, " ")
	requiredScope := scopespkg.OpenID
	found := false
	for _, scope := range scopes {
		if scope == requiredScope {
			found = true
		}
	}

	if !found {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("'scope' parameter must contain '%s', was '%s'", scopespkg.OpenID, scope)))
		return
	}

	sessionID := uuid.New().String()
	ip.Sessions[sessionID] = clientId

	code := uuid.New().String()
	ip.Codes[code] = &AuthorizeRequest{
		AcrLevel:      acrLevel,
		ClientID:      clientId,
		CodeChallenge: codeChallenge,
		Locale:        locale,
		Nonce:         nonce,
		RedirectUri:   redirect,
		SessionID:     sessionID,
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
	if ip.Config.Provider().SessionStateRequired() {
		v.Set("session_state", sessionID)
	}

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
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

	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "authorization_code":
		ip.TokenCodeGrant(w, r)
		return
	case "refresh_token":
		ip.RefreshTokenGrant(w, r)
		return
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("unsupported grant_type: " + grantType))
		return
	}
}

func (ip *IdentityProviderHandler) TokenCodeGrant(w http.ResponseWriter, r *http.Request) {
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

	err := ip.validateClientAuthentication(w, r, auth.ClientID)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	redirect := r.PostForm.Get("redirect_uri")
	if len(redirect) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing redirect_uri"))
		return
	}

	if len(auth.RedirectUri) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("redirect_uri was not set in auth code request"))
		return
	}

	if auth.RedirectUri != redirect {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("redirect_uri does not match redirect_uri used to acquire code"))
		return
	}

	codeVerifier := r.PostForm.Get("code_verifier")
	if len(codeVerifier) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing code_verifier"))
		return
	}

	expectedCodeChallenge := oauth2.S256ChallengeFromVerifier(codeVerifier)

	if expectedCodeChallenge != auth.CodeChallenge {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("code_verifier is invalid"))
		return
	}

	iat := time.Now().Truncate(time.Second)
	exp := iat.Add(ip.TokenDuration)
	sub := uuid.New().String()

	accessToken := jwt.New()
	accessToken.Set("sub", sub)
	accessToken.Set("iss", ip.Config.Provider().Issuer())
	accessToken.Set("acr", auth.AcrLevel)
	accessToken.Set("iat", iat.Unix())
	accessToken.Set("exp", exp.Unix())
	accessToken.Set("jti", uuid.NewString())
	accessToken.Set("aud", auth.ClientID)
	signedAccessToken, err := ip.signToken(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	idToken := jwt.New()
	idToken.Set("sub", sub)
	idToken.Set("iss", ip.Config.Provider().Issuer())
	idToken.Set("aud", auth.ClientID)
	idToken.Set("locale", auth.Locale)
	idToken.Set("nonce", auth.Nonce)
	idToken.Set("acr", auth.AcrLevel)
	idToken.Set("iat", iat.Unix())
	idToken.Set("exp", exp.Unix())
	idToken.Set("jti", uuid.NewString())

	// If the sid claim should be in token and in active session
	if ip.Config.Provider().SidClaimRequired() {
		idToken.Set("sid", auth.SessionID)
	}

	signedIdToken, err := ip.signToken(idToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	refreshToken := code + "some-refresh-token"

	token := &tokenResponse{
		AccessToken:  signedAccessToken,
		TokenType:    "Bearer",
		IDToken:      signedIdToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(ip.TokenDuration.Seconds()),
	}

	ip.RefreshTokens[refreshToken] = &RefreshTokenData{
		ClientID:        auth.ClientID,
		RefreshToken:    refreshToken,
		OriginalIDToken: idToken,
		SessionID:       auth.SessionID,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *IdentityProviderHandler) RefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.PostForm.Get("refresh_token")
	if len(refreshToken) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing refresh_token"))
		return
	}

	data, ok := ip.RefreshTokens[refreshToken]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("no matching refresh_token"))
		return
	}

	err := ip.validateClientAuthentication(w, r, data.ClientID)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	iat := time.Now().Truncate(time.Second)
	exp := iat.Add(ip.TokenDuration)
	sub := data.OriginalIDToken.Subject()

	accessToken := jwt.New()
	accessToken.Set("sub", sub)
	accessToken.Set("iss", ip.Config.Provider().Issuer())
	accessToken.Set("iat", iat.Unix())
	accessToken.Set("exp", exp.Unix())
	accessToken.Set("jti", uuid.NewString())
	signedAccessToken, err := ip.signToken(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	// remove provided refresh_token as it is now used
	delete(ip.RefreshTokens, refreshToken)

	// generate and store a new refresh_token
	refreshToken = uuid.NewString() + "some-new-refresh-token"

	token := &tokenResponse{
		AccessToken:  signedAccessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ExpiresIn:    int64(ip.TokenDuration.Seconds()),
	}

	ip.RefreshTokens[refreshToken] = &RefreshTokenData{
		ClientID:        data.ClientID,
		RefreshToken:    refreshToken,
		OriginalIDToken: data.OriginalIDToken,
		SessionID:       data.SessionID,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *IdentityProviderHandler) validateClientAuthentication(w http.ResponseWriter, r *http.Request, expectedClientID string) error {
	clientID := r.PostForm.Get("client_id")
	if len(clientID) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("missing client_id")
	}

	if expectedClientID != clientID {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("client_id does not match client_id for original authorization")
	}

	clientAssertion := r.PostForm.Get("client_assertion")
	if len(clientAssertion) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("missing client_assertion")
	}

	clientJwk := ip.Config.Client().ClientJWK()
	clientJwkSet := jwk.NewSet()
	clientJwkSet.AddKey(clientJwk)
	publicClientJwkSet, err := jwk.PublicSetOf(clientJwkSet)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("failed to create public client jwk set")
	}

	opts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithKeySet(publicClientJwkSet),
		jwt.WithIssuer(ip.Config.Client().ClientID()),
		jwt.WithSubject(ip.Config.Client().ClientID()),
		jwt.WithAudience(ip.Config.Provider().Issuer()),
	}
	_, err = jwt.Parse([]byte(clientAssertion), opts...)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		v := url.Values{}
		v.Set("error", "Unauthenticated")
		v.Set("error_description", "invalid client assertion")
		v.Encode()
		return fmt.Errorf("%s: %+v", v.Encode(), err)
	}

	return nil
}

func (ip *IdentityProviderHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	postLogoutRedirectURI := query.Get("post_logout_redirect_uri")
	state := query.Get("state")

	if postLogoutRedirectURI == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing required 'post_logout_redirect_uri' parameter"))
		return
	}

	if state == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing required 'state' parameter"))
		return
	}

	u, err := url.Parse(postLogoutRedirectURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("couldn't parse post_logout_redirect_uri"))
		return
	}

	v := url.Values{}
	v.Set("state", state)
	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

type relyingPartyServer struct {
	*httptest.Server
}

func newRelyingPartyServer() *relyingPartyServer {
	return &relyingPartyServer{httptest.NewUnstartedServer(nil)}
}

func (in *relyingPartyServer) GetURL() string {
	return "http://" + in.Listener.Addr().String()
}

func (in *relyingPartyServer) SetHandler(handler http.Handler) {
	in.Config = &http.Server{
		Handler: handler,
	}
}
