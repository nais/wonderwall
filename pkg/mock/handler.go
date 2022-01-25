package mock

import (
	"crypto/sha256"
	"encoding/base64"
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
	Codes         map[string]authorizeRequest
	Provider      TestProvider
	Sessions      map[string]string
	SessionStates map[string]string
}

func newIdentityProviderHandler(provider TestProvider) *identityProviderHandler {
	return &identityProviderHandler{
		Codes:         make(map[string]authorizeRequest),
		Provider:      provider,
		Sessions:      make(map[string]string),
		SessionStates: make(map[string]string),
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
	SessionState string `json:"session_state"`
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
	if ip.Provider.GetOpenIDConfiguration().GetCheckSessionIframe() {
		v.Set("session_state", ip.generateSessionState(state, fmt.Sprintf("%s://%s", u.Scheme, u.Host)))
	}

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (ip *identityProviderHandler) Jwks(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(ip.Provider.GetPublicJwkSet())
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
		if ip.Provider.GetOpenIDConfiguration().GetCheckSessionIframe() {
			v.Set("session_state", ip.SessionStates[clientID])
		}
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

	sid := uuid.New().String()

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
	if !ip.Provider.OpenIDConfiguration.GetCheckSessionIframe() || !ip.Provider.OpenIDConfiguration.SidClaimRequired() {
		idToken.Set("sid", sid)
		ip.Sessions[sid] = clientID
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

	if ip.Provider.OpenIDConfiguration.GetCheckSessionIframe() {
		sessionState := ip.SessionStates[clientID]
		token.SessionState = sessionState
		ip.Sessions[sessionState] = clientID
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *identityProviderHandler) generateSessionState(state, originUrl string) string {
	// Here, the session_state is calculated in this particular way,
	// but it is entirely up to the OP how to do it under the
	// requirements defined in this specification.
	clientId := ip.Provider.ClientConfiguration.GetClientID()
	salt := "some-salt"
	saltedString := fmt.Sprintf("%s %s %s %s", clientId, state, originUrl, salt)
	session := NewSHA256([]byte(saltedString))
	sessionState := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s.%s", session, NewSHA256([]byte(salt)))))
	ip.SessionStates[clientId] = sessionState
	return sessionState

}

func NewSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (ip *identityProviderHandler) GetClientID(sessionID string) string {
	return ip.Sessions[sessionID]
}
