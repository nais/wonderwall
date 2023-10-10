package client

import (
	"net/http"
)

type LogoutFrontchannel struct {
	sid string
}

func NewLogoutFrontchannel(r *http.Request) *LogoutFrontchannel {
	params := r.URL.Query()
	sid := params.Get("sid")

	return &LogoutFrontchannel{
		sid: sid,
	}
}

// Sid is the session identifier which SHOULD be included as a parameter in the front-channel logout request.
func (l *LogoutFrontchannel) Sid() string {
	return l.sid
}

func (l *LogoutFrontchannel) MissingSidParameter() bool {
	return len(l.sid) <= 0
}
