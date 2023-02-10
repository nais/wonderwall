package handler

import (
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/handler/autologin"
	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/session"
)

func NewHandler(
	cfg *config.Config,
	cookieOpts cookie.Options,
	jwksProvider client.JwksProvider,
	openidConfig openidconfig.Config,
	crypter crypto.Crypter,
) (*StandardHandler, error) {
	autoLogin, err := autologin.New(cfg)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	loginstatusClient := loginstatus.NewClient(cfg.Loginstatus, httpClient)

	openidClient := client.NewClient(openidConfig, loginstatusClient, jwksProvider)
	openidClient.SetHttpClient(httpClient)

	sessionHandler, err := session.NewHandler(cfg, openidConfig, crypter, openidClient)
	if err != nil {
		return nil, err
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	if err != nil {
		return nil, err
	}

	return &StandardHandler{
		autoLogin:     autoLogin,
		client:        openidClient,
		config:        cfg,
		cookieOptions: cookieOpts,
		crypter:       crypter,
		ingresses:     ingresses,
		loginstatus:   loginstatusClient,
		openidConfig:  openidConfig,
		sessions:      sessionHandler,
		upstreamProxy: NewReverseProxy(cfg.UpstreamHost),
	}, nil
}
