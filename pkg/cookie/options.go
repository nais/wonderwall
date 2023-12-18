package cookie

import (
	"net/http"
)

type Options struct {
	Domain   string
	Path     string
	SameSite http.SameSite
	Secure   bool
}

func DefaultOptions() Options {
	return Options{
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}
}

func (o Options) WithDomain(domain string) Options {
	o.Domain = domain
	return o
}

func (o Options) WithPath(path string) Options {
	o.Path = path
	return o
}

func (o Options) WithSameSite(sameSite http.SameSite) Options {
	o.SameSite = sameSite
	return o
}

func (o Options) WithSecure(secure bool) Options {
	o.Secure = secure
	return o
}
