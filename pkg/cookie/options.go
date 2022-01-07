package cookie

import (
	"net/http"
	"time"
)

type Options struct {
	ExpiresIn time.Duration
	SameSite  http.SameSite
	Secure    bool
}

func DefaultOptions() Options {
	return Options{
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}
}

func (o Options) WithSameSite(sameSite http.SameSite) Options {
	o.SameSite = sameSite
	return o
}

func (o Options) WithExpiresIn(expiresIn time.Duration) Options {
	o.ExpiresIn = expiresIn
	return o
}

func (o Options) WithSecure(secure bool) Options {
	o.Secure = secure
	return o
}
