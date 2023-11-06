package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	urllib "net/url"
	"time"

	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/acr"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/metrics"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/url"
)

var _ router.Source = &Standalone{}

type Standalone struct {
	AcrHandler     *acr.Handler
	AutoLogin      *autologin.AutoLogin
	Client         *openidclient.Client
	Config         *config.Config
	CookieOptions  cookie.Options
	Crypter        crypto.Crypter
	Ingresses      *ingress.Ingresses
	Redirect       url.Redirect
	SessionManager session.Manager
	UpstreamProxy  *ReverseProxy
}

func NewStandalone(
	cfg *config.Config,
	jwksProvider openidclient.JwksProvider,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*Standalone, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	cookieOpts := cookie.DefaultOptions()

	openidClient := openidclient.NewClient(openidConfig, jwksProvider)

	sessionManager, err := session.NewManager(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	upstream := &urllib.URL{
		Host:   cfg.UpstreamHost,
		Scheme: "http",
	}

	return &Standalone{
		AcrHandler:     acr.NewHandler(cfg),
		AutoLogin:      autoLogin,
		Client:         openidClient,
		Config:         cfg,
		CookieOptions:  cookieOpts,
		Crypter:        crypter,
		Ingresses:      ingresses,
		Redirect:       url.NewStandaloneRedirect(),
		SessionManager: sessionManager,
		UpstreamProxy:  NewReverseProxy(upstream, true),
	}, nil
}

func (s *Standalone) GetAcrHandler() *acr.Handler {
	return s.AcrHandler
}

func (s *Standalone) GetAutoLogin() *autologin.AutoLogin {
	return s.AutoLogin
}

func (s *Standalone) GetCookieOptions(r *http.Request) cookie.Options {
	if s.Config.SSO.Enabled {
		return s.CookieOptions
	}

	path := s.GetPath(r)
	return s.CookieOptions.WithPath(path)
}

func (s *Standalone) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *Standalone) GetPath(r *http.Request) string {
	return GetPath(r, s.GetIngresses())
}

func (s *Standalone) GetSession(r *http.Request) (*session.Session, error) {
	return s.SessionManager.GetOrRefresh(r)
}

func (s *Standalone) Login(w http.ResponseWriter, r *http.Request) {
	canonicalRedirect := s.Redirect.Canonical(r)
	login, err := s.Client.Login(r)
	if err != nil {
		if errors.Is(err, openidclient.ErrInvalidSecurityLevel) || errors.Is(err, openidclient.ErrInvalidLocale) {
			s.BadRequest(w, r, err)
		} else {
			s.InternalError(w, r, err)
		}

		return
	}

	opts := s.GetCookieOptions(r).
		WithExpiresIn(1 * time.Hour).
		WithSameSite(http.SameSiteNoneMode)
	err = login.SetCookie(w, opts, s.Crypter, canonicalRedirect)
	if err != nil {
		s.InternalError(w, r, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	fields := log.Fields{
		"redirect_after_login": canonicalRedirect,
	}
	mw.LogEntryFrom(r).WithFields(fields).Info("login: redirecting to identity provider")
	http.Redirect(w, r, login.AuthCodeURL, http.StatusFound)
}

func (s *Standalone) LoginCallback(w http.ResponseWriter, r *http.Request) {
	opts := s.GetCookieOptions(r)

	// unconditionally clear login cookies
	cookie.Clear(w, cookie.Login, opts.WithSameSite(http.SameSiteNoneMode))
	cookie.Clear(w, cookie.LoginLegacy, opts.WithSameSite(http.SameSiteDefaultMode))

	loginCookie, err := openid.GetLoginCookie(r, s.Crypter)
	if err != nil {
		msg := "callback: fetching login cookie"
		if errors.Is(err, http.ErrNoCookie) {
			msg += ": fallback cookie not found (user might have blocked all cookies, or the callback route was accessed before the login route)"
		}
		s.Unauthorized(w, r, fmt.Errorf("%s: %w", msg, err))
		return
	}

	loginCallback, err := s.Client.LoginCallback(r, loginCookie)
	if err != nil {
		s.InternalError(w, r, err)
		return
	}

	if err := loginCallback.IdentityProviderError(); err != nil {
		s.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	if err := loginCallback.StateMismatchError(); err != nil {
		s.Unauthorized(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	var tokens *openid.Tokens
	err = retry.Do(r.Context(), retrypkg.DefaultBackoff, func(ctx context.Context) error {
		tokens, err = loginCallback.RedeemTokens(ctx)
		return retry.RetryableError(err)
	})
	if err != nil {
		s.InternalError(w, r, fmt.Errorf("callback: redeeming tokens: %w", err))
		return
	}

	sessionLifetime := s.Config.Session.MaxLifetime

	sess, err := s.SessionManager.Create(r, tokens, sessionLifetime)
	if err != nil {
		s.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	err = sess.SetCookie(w, opts.WithExpiresIn(sessionLifetime), s.Crypter)
	if err != nil {
		s.InternalError(w, r, fmt.Errorf("callback: setting session cookie: %w", err))
		return
	}

	redirect := s.Redirect.Clean(r, loginCookie.Referer)

	amr := tokens.IDToken.GetAmrClaim()
	locale := tokens.IDToken.GetLocaleClaim()

	// TODO - remove when legacy services are sunset and shut down
	if s.Config.SSO.IsServer() && s.Config.OpenID.Provider == config.ProviderIDPorten {
		cookie.SetLegacyCookie(w, tokens.AccessToken, opts)

		if amr == "MinID Passport" {
			redirect = "https://nav.no/minid-passport"
			if locale == "en" {
				redirect = "https://nav.no/minid-passport/en"
			}
			log.WithField("redirect_to", redirect).Infof("callback: overriding redirect for MinID Passport user")
		}
	}

	fields := log.Fields{
		"redirect_to": redirect,
		"jti":         tokens.IDToken.GetJwtID(),
	}
	if amr != "" {
		fields["amr"] = amr
	}
	if locale != "" {
		fields["locale"] = locale
	}

	mw.LogEntryFrom(r).WithFields(fields).Info("callback: successful login")
	metrics.ObserveLogin(amr, redirect)
	cookie.Clear(w, cookie.Retry, s.GetCookieOptions(r))
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Standalone) Logout(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	logout, err := s.Client.Logout(r)
	if err != nil {
		s.InternalError(w, r, err)
		return
	}

	var idToken string

	sess, _ := s.SessionManager.Get(r)
	if sess != nil {
		idToken = sess.IDToken()

		err := s.SessionManager.Delete(r.Context(), sess)
		if err != nil && !errors.Is(err, session.ErrNotFound) {
			s.InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}

		logger.Debug("logout: session deleted")
	}

	cookie.Clear(w, cookie.Session, s.GetCookieOptions(r))

	// only set a canonical redirect if it was provided in the request as a query parameter
	canonicalRedirect := r.URL.Query().Get(url.RedirectQueryParameter)
	if canonicalRedirect != "" {
		canonicalRedirect = s.Redirect.Canonical(r)
	}

	opts := s.CookieOptions.WithExpiresIn(5 * time.Minute)
	err = logout.SetCookie(w, opts, s.Crypter, canonicalRedirect)
	if err != nil {
		s.InternalError(w, r, fmt.Errorf("logout: setting logout cookie: %w", err))
		return
	}

	logger.WithField("redirect_after_logout", canonicalRedirect).
		Info("logout: redirecting to identity provider for global/single-logout")
	metrics.ObserveLogout(metrics.LogoutOperationSelfInitiated)
	http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusFound)
}

func (s *Standalone) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	sess, _ := s.SessionManager.Get(r)
	if sess != nil {
		err := s.SessionManager.Delete(r.Context(), sess)
		if err != nil && !errors.Is(err, session.ErrNotFound) {
			s.InternalError(w, r, fmt.Errorf("logout/local: destroying session: %w", err))
			return
		}

		logger.Debug("logout/local: session deleted")
	}

	cookie.Clear(w, cookie.Session, s.GetCookieOptions(r))
	logger.Debug("logout/local: successful local logout")
	metrics.ObserveLogout(metrics.LogoutOperationLocal)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Standalone) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	cookie.Clear(w, cookie.Logout, s.CookieOptions)

	logoutCookie, err := openid.GetLogoutCookie(r, s.Crypter)
	if err != nil {
		logger.Debugf("logout/callback: getting cookie: %+v; ignoring...", err)
	}

	logoutCallback := s.Client.LogoutCallback(r, logoutCookie, s.Redirect)
	redirect := logoutCallback.PostLogoutRedirectURI()

	cookie.Clear(w, cookie.Retry, s.GetCookieOptions(r))
	logger.Infof("logout/callback: redirecting to %q", redirect)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Standalone) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, s.GetCookieOptions(r))

	lfc := s.Client.LogoutFrontchannel(r)
	if lfc.MissingSidParameter() {
		logger.Debugf("front-channel logout: sid parameter not found in request; ignoring")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	id := lfc.Sid()
	err := s.SessionManager.DeleteForExternalID(r.Context(), id)
	if err != nil {
		logger.Warnf("front-channel logout: destroying session with id %q: %+v", id, err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	cookie.Clear(w, cookie.Retry, s.GetCookieOptions(r))
	metrics.ObserveLogout(metrics.LogoutOperationFrontChannel)
	w.WriteHeader(http.StatusOK)
}

func (s *Standalone) Session(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	sess, err := s.SessionManager.Get(r)
	if err != nil && !errors.Is(err, session.ErrInactive) {
		handleGetSessionError("session/info", w, r, err)
		return
	}

	err = s.sessionWriteMetadataResponse(w, r, sess)
	if err != nil {
		logger.Warnf("session/info: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Standalone) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.Config.Session.Refresh {
		http.NotFound(w, r)
		return
	}

	logger := mw.LogEntryFrom(r)

	sess, err := s.SessionManager.Get(r)
	if err != nil {
		handleGetSessionError("session/refresh", w, r, err)
		return
	}

	sess, err = s.SessionManager.Refresh(r, sess)
	if err != nil {
		if errors.Is(err, session.ErrInvalidExternal) || errors.Is(err, session.ErrInvalid) || errors.Is(err, session.ErrNotFound) {
			logger.Infof("session/refresh: refreshing: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Warnf("session/refresh: refreshing: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = s.sessionWriteMetadataResponse(w, r, sess)
	if err != nil {
		logger.Warnf("session/refresh: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Standalone) sessionWriteMetadataResponse(w http.ResponseWriter, r *http.Request, sess *session.Session) error {
	w.Header().Set("Content-Type", "application/json")

	if !s.Config.Session.Refresh {
		return json.NewEncoder(w).Encode(sess.MetadataVerbose())
	}

	metadata := sess.MetadataVerboseRefresh()
	if !s.Config.Session.RefreshAuto {
		metadata.Tokens.NextAutoRefreshInSeconds = int64(-1)
	}

	return json.NewEncoder(w).Encode(metadata)
}

// Wildcard proxies all requests to an upstream server.
func (s *Standalone) Wildcard(w http.ResponseWriter, r *http.Request) {
	s.UpstreamProxy.Handler(s, w, r)
}

func handleGetSessionError(route string, w http.ResponseWriter, r *http.Request, err error) {
	logger := mw.LogEntryFrom(r)

	if errors.Is(err, session.ErrNotFound) {
		logger.Debugf("%s: getting session: %+v", route, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if errors.Is(err, session.ErrInvalid) {
		logger.Infof("%s: getting session: %+v", route, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	logger.Warnf("%s: getting session: %+v", route, err)
	w.WriteHeader(http.StatusInternalServerError)
}
