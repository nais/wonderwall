package session

import (
	"context"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
)

type Store interface {
	Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error
	Read(ctx context.Context, key string) (*EncryptedData, error)
	Delete(ctx context.Context, keys ...string) error
}

type EncryptedData struct {
	Data string `json:"data"`
}

var _ encoding.BinaryMarshaler = &EncryptedData{}
var _ encoding.BinaryUnmarshaler = &EncryptedData{}

func (in *EncryptedData) MarshalBinary() ([]byte, error) {
	return json.Marshal(in)
}

func (in *EncryptedData) UnmarshalBinary(bytes []byte) error {
	return json.Unmarshal(bytes, in)
}

func (in *EncryptedData) Decrypt(crypter crypto.Crypter) (*Data, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil {
		return nil, err
	}

	rawData, err := crypter.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	var data Data
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

type Data struct {
	ExternalSessionID string `json:"external_session_id"`
	AccessToken       string `json:"access_token"`
	IDToken           string `json:"id_token"`
}

func NewData(externalSessionID, accessToken, idToken string) *Data {
	return &Data{
		ExternalSessionID: externalSessionID,
		AccessToken:       accessToken,
		IDToken:           idToken,
	}
}

func (in *Data) Encrypt(crypter crypto.Crypter) (*EncryptedData, error) {
	bytes, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypter.Encrypt(bytes)
	if err != nil {
		return nil, err
	}

	return &EncryptedData{
		Data: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
