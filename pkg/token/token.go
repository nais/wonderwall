package token

import (
	"golang.org/x/oauth2"
	"time"
)

type TokenBin struct {
	RefreshToken *refreshToken
	AccessToken  *accessToken
	Expiry       time.Time
}

func NewRefreshedTokenBin(tokenResponse *oauth2.Token, currentRefreshToken, currentAccessToken string) (*TokenBin, error) {
	return &TokenBin{
		RefreshToken: &refreshToken{
			otherToken: currentRefreshToken,
			refresh:    false,
			rawToken:   tokenResponse.RefreshToken,
		},
		AccessToken: &accessToken{
			otherToken: currentAccessToken,
			refresh:    false,
			rawToken:   tokenResponse.AccessToken,
		},
		Expiry: tokenResponse.Expiry,
	}, nil
}

func (in *TokenBin) Refreshed() bool {
	return in.RefreshToken.refresh || in.AccessToken.refresh
}

type refreshToken struct {
	otherToken string
	refresh    bool
	rawToken   string
}

func (in *accessToken) Refreshed() bool {
	in.refresh = in.rawToken != in.otherToken
	return in.refresh
}

func (in *accessToken) GetRaw() string {
	return in.rawToken
}

type accessToken struct {
	otherToken string
	refresh    bool
	rawToken   string
}

func (in *refreshToken) Refreshed() bool {
	in.refresh = in.rawToken != in.otherToken
	return in.refresh
}

func (in *refreshToken) GetRaw() string {
	return in.rawToken
}
