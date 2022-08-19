package session

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
)

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
	ExternalSessionID string   `json:"external_session_id"`
	AccessToken       string   `json:"access_token"`
	IDToken           string   `json:"id_token"`
	RefreshToken      string   `json:"refresh_token"`
	IDTokenJwtID      string   `json:"id_token_jwt_id"`
	Metadata          Metadata `json:"metadata"`
}

func NewData(externalSessionID string, tokens *openid.Tokens, metadata *Metadata) *Data {
	data := &Data{
		ExternalSessionID: externalSessionID,
		AccessToken:       tokens.AccessToken,
		IDToken:           tokens.IDToken.GetSerialized(),
		IDTokenJwtID:      tokens.IDToken.GetJwtID(),
		RefreshToken:      tokens.RefreshToken,
	}

	if metadata != nil {
		data.Metadata = *metadata
	}

	return data
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

type Metadata struct {
	CreatedAt   int64 `json:"created_at"`
	RefreshedAt int64 `json:"refreshed_at"`
	ExpiresAt   int64 `json:"expires_at"`
}

func NewMetadata(expiresAt time.Time) *Metadata {
	return &Metadata{
		CreatedAt:   time.Now().Unix(),
		RefreshedAt: time.Now().Unix(),
		ExpiresAt:   expiresAt.Unix(),
	}
}

func (in *Metadata) UpdateRefreshedAt() {
	in.RefreshedAt = time.Now().Unix()
}
