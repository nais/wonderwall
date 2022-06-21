package router

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
	"github.com/nais/wonderwall/pkg/router/paths"
	"github.com/nais/wonderwall/pkg/router/request"
)

type ErrorPage struct {
	CorrelationID string
	RetryURI      string
}

//go:embed templates/error.gohtml
var errorGoHtml string
var errorTemplate *template.Template

func init() {
	var err error

	errorTemplate = template.New("error")
	errorTemplate, err = errorTemplate.Parse(errorGoHtml)
	if err != nil {
		log.Fatalf("parsing error template: %+v", err)
	}
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, statusCode int, cause error, level zerolog.Level) {
	logger := logentry.LogEntry(r.Context())
	logger.WithLevel(level).Stack().Err(cause).Msgf("error in route: %+v", cause)

	if len(h.Config.ErrorRedirectURI) > 0 {
		err := h.customErrorRedirect(w, r, statusCode)
		if err == nil {
			return
		}
	}

	h.defaultErrorResponse(w, r, statusCode)
}

func (h *Handler) defaultErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int) {
	w.WriteHeader(statusCode)

	loginCookie, err := h.getLoginCookie(r)
	if err != nil {
		loginCookie = nil
	}

	errorPage := ErrorPage{
		CorrelationID: middleware.GetReqID(r.Context()),
		RetryURI:      RetryURI(r, h.Config.Ingress, loginCookie),
	}
	err = errorTemplate.Execute(w, errorPage)
	if err != nil {
		log.Errorf("executing error template: %+v", err)
	}
}

func (h *Handler) customErrorRedirect(w http.ResponseWriter, r *http.Request, statusCode int) error {
	override, err := url.Parse(h.Config.ErrorRedirectURI)
	if err != nil {
		return err
	}
	// strip scheme and host to avoid cross-domain redirects
	override.Scheme = ""
	override.Host = ""

	query := override.Query()
	query.Add("correlation_id", middleware.GetReqID(r.Context()))
	query.Add("status_code", strconv.Itoa(statusCode))

	override.RawQuery = query.Encode()

	errorRedirectURI := override.String()
	http.Redirect(w, r, errorRedirectURI, http.StatusFound)
	return nil
}

func (h *Handler) InternalError(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusInternalServerError, cause, zerolog.ErrorLevel)
}

func (h *Handler) BadRequest(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusBadRequest, cause, zerolog.ErrorLevel)
}

func (h *Handler) Unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	h.respondError(w, r, http.StatusUnauthorized, cause, zerolog.WarnLevel)
}

// RetryURI returns a URI that should retry the desired route that failed.
// It only handles the routes exposed by Wonderwall, i.e. `/oauth2/*`. As these routes
// are related to the authentication flow, we default to redirecting back to the handled
// `/oauth2/login` endpoint unless the original request attempted to reach the logout-flow.
func RetryURI(r *http.Request, ingress string, loginCookie *openid.LoginCookie) string {
	retryURI := r.URL.Path
	prefix := config.ParseIngress(ingress)

	if strings.HasSuffix(retryURI, paths.OAuth2+paths.Logout) || strings.HasSuffix(retryURI, paths.OAuth2+paths.FrontChannelLogout) {
		return prefix + retryURI
	}

	redirect := request.CanonicalRedirectURL(r, ingress)

	if loginCookie != nil && len(loginCookie.Referer) > 0 {
		redirect = loginCookie.Referer
	}

	retryURI = fmt.Sprintf(prefix + paths.OAuth2 + paths.Login)
	retryURI = retryURI + fmt.Sprintf("?%s=%s", request.RedirectURLParameter, redirect)
	return retryURI
}
