package session

import (
	"context"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/jwt"
)

type Store interface {
	Write(ctx context.Context, key string, value *EncryptedData, expiration time.Duration) error
	Read(ctx context.Context, key string) (*EncryptedData, error)
	Delete(ctx context.Context, keys ...string) error
}

func NewStore(cfg *config.Config) Store {
	if len(cfg.Redis.Address) == 0 {
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
		return NewMemory()
	}

	redisClient, err := cfg.Redis.Client()
	if err != nil {
		log.Fatalf("Failed to configure Redis: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err = redisClient.Ping(ctx).Err()
	if err != nil {
		log.Warnf("Failed to connect to configured Redis, using cookie fallback: %v", err)
	} else {
		log.Infof("Using Redis as session backing store")
	}

	return NewRedis(redisClient)
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
	ExternalSessionID string     `json:"external_session_id"`
	AccessToken       string     `json:"access_token"`
	IDToken           string     `json:"id_token"`
	RefreshToken      string     `json:"refresh_token"`
	Claims            jwt.Claims `json:"claims"`
	Metadata          Metadata   `json:"metadata"`
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

func NewData(externalSessionID string, tokens *jwt.Tokens, refreshToken string, metadata *Metadata) *Data {
	data := &Data{
		ExternalSessionID: externalSessionID,
		AccessToken:       tokens.AccessToken.GetSerialized(),
		IDToken:           tokens.IDToken.GetSerialized(),
		RefreshToken:      refreshToken,
		Claims:            tokens.Claims(),
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
