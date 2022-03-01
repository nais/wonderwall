package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type identityProviderHandler struct {
	Codes    map[string]authorizeRequest
	Provider TestProvider
	Sessions map[string]string
}

func newIdentityProviderHandler(provider TestProvider) *identityProviderHandler {
	return &identityProviderHandler{
		Codes:    make(map[string]authorizeRequest),
		Provider: provider,
		Sessions: make(map[string]string),
	}
}

type authorizeRequest struct {
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

func (ip *identityProviderHandler) signToken(token jwt.Token) (string, error) {
	privateJwkSet := *ip.Provider.PrivateJwkSet()
	signer, ok := privateJwkSet.Get(0)
	if !ok {
		return "", fmt.Errorf("could not get signer")
	}

	signedToken, err := jwt.Sign(token, jwa.RS256, signer)
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}

func (ip *identityProviderHandler) Authorize(w http.ResponseWriter, r *http.Request) {
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
	ip.Codes[code] = authorizeRequest{
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

func (ip *identityProviderHandler) Jwks(w http.ResponseWriter, r *http.Request) {
	jwks, _ := ip.Provider.GetPublicJwkSet(r.Context())
	json.NewEncoder(w).Encode(jwks)
}

func (ip *identityProviderHandler) Token(w http.ResponseWriter, r *http.Request) {
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

	clientJwk := ip.Provider.GetClientConfiguration().GetClientJWK()
	clientJwkSet := jwk.NewSet()
	clientJwkSet.Add(clientJwk)
	publicClientJwkSet, err := jwk.PublicSetOf(clientJwkSet)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to create public client jwk set"))
		return
	}

	opts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithKeySet(publicClientJwkSet),
		jwt.WithIssuer(ip.Provider.GetClientConfiguration().GetClientID()),
		jwt.WithSubject(ip.Provider.GetClientConfiguration().GetClientID()),
		jwt.WithClaimValue("scope", ip.Provider.GetClientConfiguration().GetScopes().String()),
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
		AccessToken: signedAccessToken,
		TokenType:   "Bearer",
		IDToken:     signedIdToken,
		ExpiresIn:   expires,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}
