package reverseproxy

import (
	"errors"
	"net/http"
	"net/http/httputil"

	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/handler/url"
	"github.com/nais/wonderwall/pkg/loginstatus"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

type Source interface {
	GetAutoLogin() *autologin.AutoLogin
	GetLoginstatus() *loginstatus.Loginstatus
	GetPath(r *http.Request) string
	GetSessions() *session.Handler
}

type ReverseProxy struct {
	*httputil.ReverseProxy
}

func New(upstreamHost string) *ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Delete incoming authentication
			r.Header.Del("authorization")
			// Instruct http.ReverseProxy to not modify X-Forwarded-For header
			r.Header["X-Forwarded-For"] = nil
			// Request should go to correct host
			r.URL.Host = upstreamHost
			r.URL.Scheme = "http"

			accessToken, ok := mw.AccessTokenFrom(r.Context())
			if ok {
				r.Header.Set("authorization", "Bearer "+accessToken)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}
	return &ReverseProxy{rp}
}

func (rp *ReverseProxy) Handler(src Source, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)
	isAuthenticated := false

	accessToken, err := src.GetSessions().GetAccessToken(r)
	if err == nil {
		// add authentication if session cookie and token checks out
		isAuthenticated = true

		// force new authentication if loginstatus is enabled and cookie isn't set
		if src.GetLoginstatus().NeedsLogin(r) {
			isAuthenticated = false
			logger.Info("default: loginstatus was enabled, but no matching cookie was found; state is now unauthenticated")
		}
	} else if errors.Is(err, session.UnexpectedError) {
		logger.Errorf("default: getting session: %+v", err)
	}

	if src.GetAutoLogin().NeedsLogin(r, isAuthenticated) {
		logger.Debug("default: auto-login is enabled; request does not match any configured ignorable paths")

		redirectTarget := r.URL.String()
		path := src.GetPath(r)

		loginUrl := url.LoginURL(path, redirectTarget)
		http.Redirect(w, r, loginUrl, http.StatusTemporaryRedirect)
		return
	}

	ctx := r.Context()

	if isAuthenticated {
		ctx = mw.WithAccessToken(ctx, accessToken)
	}

	rp.ServeHTTP(w, r.WithContext(ctx))
}
