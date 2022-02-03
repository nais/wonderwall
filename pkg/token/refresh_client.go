package token

import (
	"context"
	"fmt"
	"github.com/nais/wonderwall/pkg/openid"
	"golang.org/x/oauth2"
	"time"
)

type RefreshClient struct {
	TokenSource oauth2.TokenSource
}

func NewRefreshClient(ctx context.Context, config oauth2.Config, provider openid.Provider, currRefreshToken string) (*RefreshClient, error) {
	clientAssertion, err := openid.ClientAssertion(provider, time.Second*30)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	config.ClientSecret = clientAssertion

	cfg := &oauth2.Token{
		RefreshToken: currRefreshToken,
	}

	return &RefreshClient{
		TokenSource: oauth2.ReuseTokenSource(nil,
			config.TokenSource(ctx, cfg),
		),
	}, nil
}

func (in *RefreshClient) Token(refreshToken, accessToken string) (*TokenBin, error) {
	rt, err := in.TokenSource.Token()

	if err != nil {
		return nil, fmt.Errorf("refresh token request: %v", err)
	}

	return NewTokenBin(rt, refreshToken, accessToken), nil
}
