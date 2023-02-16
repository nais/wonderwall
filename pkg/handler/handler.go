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
	"github.com/nais/wonderwall/pkg/handler/autologin"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
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
	AutoLogin     *autologin.AutoLogin
	Client        *openidclient.Client
	Config        *config.Config
	CookieOptions cookie.Options
	Crypter       crypto.Crypter
	Ingresses     *ingress.Ingresses
	OpenidConfig  openidconfig.Config
	Redirect      url.Redirect
	Sessions      *session.Handler
	UpstreamProxy *ReverseProxy
}

type LogoutOptions struct {
	GlobalLogout bool
}

func NewStandalone(
	cfg *config.Config,
	cookieOpts cookie.Options,
	jwksProvider openidclient.JwksProvider,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*Standalone, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	openidClient := openidclient.NewClient(openidConfig, jwksProvider)
	openidClient.SetHttpClient(&http.Client{
		Timeout: time.Second * 10,
	})

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
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
		AutoLogin:     autoLogin,
		Client:        openidClient,
		Config:        cfg,
		CookieOptions: cookieOpts,
		Crypter:       crypter,
		Ingresses:     ingresses,
		OpenidConfig:  openidConfig,
		Redirect:      url.NewStandaloneRedirect(ingresses),
		Sessions:      sessionHandler,
		UpstreamProxy: NewReverseProxy(upstream, true),
	}, nil
}

func (s *Standalone) GetAutoLogin() *autologin.AutoLogin {
	return s.AutoLogin
}

func (s *Standalone) GetClient() *openidclient.Client {
	return s.Client
}

func (s *Standalone) GetCookieOptions() cookie.Options {
	return s.CookieOptions
}

func (s *Standalone) GetCookieOptsPathAware(r *http.Request) cookie.Options {
	if s.Config.SSO.Enabled {
		return s.GetCookieOptions()
	}

	path := s.GetPath(r)
	return s.CookieOptions.WithPath(path)
}

func (s *Standalone) GetCrypter() crypto.Crypter {
	return s.Crypter
}

func (s *Standalone) GetErrorHandler() errorhandler.Handler {
	return errorhandler.New(s)
}

func (s *Standalone) GetIngresses() *ingress.Ingresses {
	return s.Ingresses
}

func (s *Standalone) GetPath(r *http.Request) string {
	path, ok := mw.PathFrom(r.Context())
	if !ok {
		path = s.Ingresses.MatchingPath(r)
	}

	return path
}

func (s *Standalone) GetRedirect() url.Redirect {
	return s.Redirect
}

func (s *Standalone) GetSessions() *session.Handler {
	return s.Sessions
}

func (s *Standalone) GetSessionConfig() config.Session {
	return s.Config.Session
}

func (s *Standalone) Login(w http.ResponseWriter, r *http.Request) {
	canonicalRedirect := s.GetRedirect().Canonical(r)
	login, err := s.GetClient().Login(r)
	if err != nil {
		if errors.Is(err, openidclient.ErrInvalidSecurityLevel) || errors.Is(err, openidclient.ErrInvalidLocale) {
			s.GetErrorHandler().BadRequest(w, r, err)
		} else {
			s.GetErrorHandler().InternalError(w, r, err)
		}

		return
	}

	opts := s.GetCookieOptsPathAware(r).
		WithExpiresIn(1 * time.Hour).
		WithSameSite(http.SameSiteNoneMode)
	err = login.SetCookie(w, opts, s.GetCrypter(), canonicalRedirect)
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	fields := log.Fields{
		"redirect_after_login": canonicalRedirect,
	}
	mw.LogEntryFrom(r).WithFields(fields).Info("login: redirecting to identity provider")
	http.Redirect(w, r, login.AuthCodeURL(), http.StatusTemporaryRedirect)
}

func (s *Standalone) LoginCallback(w http.ResponseWriter, r *http.Request) {
	opts := s.GetCookieOptsPathAware(r)

	// unconditionally clear login cookies
	cookie.Clear(w, cookie.Login, opts.WithSameSite(http.SameSiteNoneMode))
	cookie.Clear(w, cookie.LoginLegacy, opts.WithSameSite(http.SameSiteDefaultMode))

	loginCookie, err := openid.GetLoginCookie(r, s.GetCrypter())
	if err != nil {
		msg := "callback: fetching login cookie"
		if errors.Is(err, http.ErrNoCookie) {
			msg += ": fallback cookie not found (user might have blocked all cookies, or the callback route was accessed before the login route)"
		}
		s.GetErrorHandler().Unauthorized(w, r, fmt.Errorf("%s: %w", msg, err))
		return
	}

	loginCallback, err := s.GetClient().LoginCallback(r, loginCookie)
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, err)
		return
	}

	if err := loginCallback.IdentityProviderError(); err != nil {
		s.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	if err := loginCallback.StateMismatchError(); err != nil {
		s.GetErrorHandler().Unauthorized(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	var tokens *openid.Tokens
	err = retry.Do(r.Context(), retrypkg.DefaultBackoff, func(ctx context.Context) error {
		tokens, err = loginCallback.RedeemTokens(ctx)
		return retry.RetryableError(err)
	})
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: redeeming tokens: %w", err))
		return
	}

	sessionLifetime := s.GetSessionConfig().MaxLifetime

	ticket, err := s.GetSessions().Create(r, tokens, sessionLifetime)
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	err = ticket.Set(w, opts.WithExpiresIn(sessionLifetime), s.GetCrypter())
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: setting session cookie: %w", err))
		return
	}

	redirect := s.GetRedirect().Clean(r, loginCookie.Referer)

	fields := log.Fields{
		"redirect_to": redirect,
		"jti":         tokens.IDToken.GetJwtID(),
	}

	mw.LogEntryFrom(r).WithFields(fields).Info("callback: successful login")
	metrics.ObserveLogin()
	cookie.Clear(w, cookie.Retry, s.GetCookieOptsPathAware(r))
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func (s *Standalone) Logout(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: true,
	}
	s.logout(w, r, opts)
}

func (s *Standalone) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	opts := LogoutOptions{
		GlobalLogout: false,
	}
	s.logout(w, r, opts)
}

func (s *Standalone) logout(w http.ResponseWriter, r *http.Request, opts LogoutOptions) {
	logger := mw.LogEntryFrom(r)
	logout, err := s.GetClient().Logout(r)
	if err != nil {
		s.GetErrorHandler().InternalError(w, r, err)
		return
	}

	var idToken string

	sessions := s.GetSessions()

	ticket, err := sessions.GetTicket(r)
	if err == nil {
		sessionData, err := sessions.Get(r, ticket)
		if err == nil && sessionData != nil {
			idToken = sessionData.IDToken

			err = sessions.Destroy(r, ticket.Key())
			if err != nil && !errors.Is(err, session.ErrKeyNotFound) {
				s.GetErrorHandler().InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
				return
			}

			logger.WithField("jti", sessionData.IDTokenJwtID).
				Info("logout: successful local logout")
			metrics.ObserveLogout(metrics.LogoutOperationLocal)
		}
	}

	cookie.Clear(w, cookie.Session, s.GetCookieOptsPathAware(r))

	if opts.GlobalLogout {
		logger.Debug("logout: redirecting to identity provider for global/single-logout")
		metrics.ObserveLogout(metrics.LogoutOperationSelfInitiated)
		http.Redirect(w, r, logout.SingleLogoutURL(idToken), http.StatusTemporaryRedirect)
	}
}

func (s *Standalone) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	redirect := s.GetClient().LogoutCallback(r).PostLogoutRedirectURI()

	cookie.Clear(w, cookie.Retry, s.GetCookieOptsPathAware(r))
	mw.LogEntryFrom(r).Debugf("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func (s *Standalone) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, s.GetCookieOptsPathAware(r))

	sessions := s.GetSessions()
	client := s.GetClient()

	getSessionKey := func(r *http.Request) (string, error) {
		lfc := client.LogoutFrontchannel(r)

		if lfc.MissingSidParameter() {
			ticket, err := sessions.GetTicket(r)
			if err != nil {
				return ticket.Key(), nil
			}
			return "", fmt.Errorf("neither sid parameter nor session ticket found in request: %w", err)
		}

		sid := lfc.Sid()
		return sessions.Key(sid), nil
	}

	key, err := getSessionKey(r)
	if err != nil {
		logger.Debugf("front-channel logout: getting session key: %+v; ignoring", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	err = sessions.Destroy(r, key)
	if err != nil {
		logger.Warnf("front-channel logout: destroying session: %+v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	cookie.Clear(w, cookie.Retry, s.GetCookieOptsPathAware(r))
	metrics.ObserveLogout(metrics.LogoutOperationFrontChannel)
	w.WriteHeader(http.StatusOK)
}

func (s *Standalone) Session(w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	ticket, err := s.GetSessions().GetTicket(r)
	if err != nil {
		logger.Infof("session/refresh: getting ticket: %+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, err := s.GetSessions().Get(r, ticket)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidSession), errors.Is(err, session.ErrKeyNotFound):
			logger.Infof("session/info: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			logger.Warnf("session/info: getting session: %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if s.GetSessionConfig().Refresh {
		err = json.NewEncoder(w).Encode(data.Metadata.VerboseWithRefresh())
	} else {
		err = json.NewEncoder(w).Encode(data.Metadata.Verbose())
	}

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

	ticket, err := s.GetSessions().GetTicket(r)
	if err != nil {
		logger.Infof("session/refresh: getting ticket: %+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, err := s.GetSessions().Get(r, ticket)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidSession), errors.Is(err, session.ErrKeyNotFound):
			logger.Infof("session/refresh: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			logger.Warnf("session/refresh: getting session: %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	data, err = s.GetSessions().Refresh(r, ticket, data)
	if err != nil {
		if errors.Is(err, session.ErrInvalidIdpState) || errors.Is(err, session.ErrInvalidSession) {
			logger.Infof("session/refresh: refreshing: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Warnf("session/refresh: refreshing: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data.Metadata.VerboseWithRefresh())
	if err != nil {
		logger.Warnf("session/refresh: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Standalone) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	s.UpstreamProxy.Handler(s, w, r)
}
