package refresh

import (
	"context"
	"fmt"
	"github.com/nais/wonderwall/pkg/openid"
	"golang.org/x/oauth2"
	"time"
)

type Client struct {
	TokenSource oauth2.TokenSource
}

func NewRefreshClient(ctx context.Context, config oauth2.Config, provider openid.Provider, currRefreshToken string) (*Client, error) {
	clientAssertion, err := openid.ClientAssertion(provider, time.Second*30)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	config.ClientSecret = clientAssertion

	cfg := &oauth2.Token{
		RefreshToken: currRefreshToken,
	}

	return &Client{
		TokenSource: oauth2.ReuseTokenSource(nil,
			config.TokenSource(ctx, cfg),
		),
	}, nil
}

func (in *Client) Token(refreshToken, accessToken string) (*TokenCollector, error) {
	rt, err := in.TokenSource.Token()

	if err != nil {
		return nil, fmt.Errorf("refresh token request: %v", err)
	}

	return NewTokenCollector(rt, refreshToken, accessToken), nil
}
