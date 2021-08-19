package router

import (
	"strings"
)

type SpaceDelimitedArray []string

type JWTTokenRequest struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Scopes    string `json:"scope"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return []byte(strings.Join(s, " ")), nil
}
