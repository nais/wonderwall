package session

import (
	"context"
	"encoding"
	"encoding/json"
	"golang.org/x/oauth2"
	"time"
)

type Session interface {
	Write(ctx context.Context, key string, value *Data, expiration time.Duration) error
	Read(ctx context.Context, key string) (*Data, error)
	Delete(ctx context.Context, keys ...string) error
}

type Data struct {
	ID    string
	Token *oauth2.Token
}

var _ encoding.BinaryMarshaler = &Data{}
var _ encoding.BinaryUnmarshaler = &Data{}

func (data *Data) MarshalBinary() ([]byte, error) {
	return json.Marshal(data)
}

func (data *Data) UnmarshalBinary(bytes []byte) error {
	return json.Unmarshal(bytes, data)
}
