package auth

import (
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func X() {
	_ = jose.Header{}
	_ = jwt.Audience{}
}
