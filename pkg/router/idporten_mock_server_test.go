package router_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/nais/wonderwall/pkg/config"
)

type IDPorten struct {
	Clients  map[string]string
	Config   config.IDPorten
	Codes    map[string]AuthRequest
	Keys     jwk.Set
	Sessions map[string]string
}

type AuthRequest struct {
	AcrLevel      string
	CodeChallenge string
	Locale        string
	Nonce         string
}

func NewIDPorten(clients map[string]string, config config.IDPorten) *IDPorten {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		panic(err)
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		panic(err)
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	if err != nil {
		panic(err)
	}

	keys := jwk.NewSet()
	keys.Add(key)

	return &IDPorten{
		Clients:  clients,
		Codes:    make(map[string]AuthRequest),
		Config:   config,
		Keys:     keys,
		Sessions: make(map[string]string),
	}
}

type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func (ip *IDPorten) signToken(token jwt.Token) (string, error) {
	signer, ok := ip.Keys.Get(0)
	if !ok {
		return "", fmt.Errorf("could not get signer")
	}

	signedToken, err := jwt.Sign(token, jwa.RS256, signer)
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}

func (ip *IDPorten) Token(w http.ResponseWriter, r *http.Request) {
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
	sid := uuid.New().String()

	accessToken := jwt.New()
	accessToken.Set("sub", sub)
	accessToken.Set("iss", ip.Config.WellKnown.Issuer)
	accessToken.Set("acr", auth.AcrLevel)
	accessToken.Set("iat", time.Now().Unix())
	accessToken.Set("exp", time.Now().Unix()+expires)
	signedAccessToken, err := ip.signToken(accessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	idToken := jwt.New()
	idToken.Set("sub", sub)
	idToken.Set("iss", ip.Config.WellKnown.Issuer)
	idToken.Set("aud", ip.Config.ClientID)
	idToken.Set("locale", auth.Locale)
	idToken.Set("nonce", auth.Nonce)
	idToken.Set("acr", auth.AcrLevel)
	idToken.Set("iat", time.Now().Unix())
	idToken.Set("exp", time.Now().Unix()+expires)
	idToken.Set("sid", sid)

	signedIdToken, err := ip.signToken(idToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not sign access token: " + err.Error()))
		return
	}

	ip.Sessions[sid] = ip.Config.ClientID
	token := &TokenJSON{
		AccessToken: signedAccessToken,
		TokenType:   "Bearer",
		IDToken:     signedIdToken,
		ExpiresIn:   expires,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *IDPorten) Authorize(w http.ResponseWriter, r *http.Request) {
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
	ip.Codes[code] = AuthRequest{
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

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (ip *IDPorten) Jwks(w http.ResponseWriter, r *http.Request) {
	publicSet, err := jwk.PublicSetOf(ip.Keys)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("could not create public set: " + err.Error()))
		return
	}
	json.NewEncoder(w).Encode(publicSet)
}

func idportenRouter(ip *IDPorten) chi.Router {
	r := chi.NewRouter()
	r.Get("/authorize", ip.Authorize)
	r.Post("/token", ip.Token)
	r.Get("/jwks", ip.Jwks)
	return r
}
