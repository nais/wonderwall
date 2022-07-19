package client

import "net/http"

type LogoutFrontchannel interface {
	// Sid is the session identifier which SHOULD be included as a parameter in the front-channel logout request.
	Sid() string
	MissingSidParameter() bool
}

type logoutFrontchannel struct {
	sid string
}

func NewLogoutFrontchannel(r *http.Request) LogoutFrontchannel {
	params := r.URL.Query()
	sid := params.Get("sid")

	return &logoutFrontchannel{
		sid: sid,
	}
}

func (l *logoutFrontchannel) Sid() string {
	return l.sid
}

func (l *logoutFrontchannel) MissingSidParameter() bool {
	return len(l.sid) <= 0
}
