package jwt

type Type int

const (
	TypeIDToken Type = iota
	TypeAccessToken
)
