package session

import (
	"context"
	"encoding"
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

type Store interface {
	Write(ctx context.Context, key string, value *Data, expiration time.Duration) error
	Read(ctx context.Context, key string) (*Data, error)
	Delete(ctx context.Context, keys ...string) error
}

type Data struct {
	ExternalSessionID string
	OAuth2Token       *oauth2.Token
	IDTokenSerialized string
}

var _ encoding.BinaryMarshaler = &Data{}
var _ encoding.BinaryUnmarshaler = &Data{}

func (data *Data) MarshalBinary() ([]byte, error) {
	return json.Marshal(data)
}

func (data *Data) UnmarshalBinary(bytes []byte) error {
	return json.Unmarshal(bytes, data)
}
