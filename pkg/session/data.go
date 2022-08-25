package session

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
)

const (
	RefreshMinInterval = 1 * time.Minute
	RefreshLeeway      = 5 * time.Minute
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

func (in *Data) HasAccessToken() bool {
	return len(in.AccessToken) > 0
}

func (in *Data) HasRefreshToken() bool {
	return len(in.RefreshToken) > 0
}

type Metadata struct {
	// SessionCreatedAt is the time when the session was created.
	SessionCreatedAt time.Time `json:"session_created_at"`
	// SessionEndsAt is the time when the session will end, i.e. the absolute lifetime/time-to-live for the session.
	SessionEndsAt time.Time `json:"session_ends_at"`
	// TokensExpireAt is the time when the tokens within the session expires.
	TokensExpireAt time.Time `json:"tokens_expire_at"`
	// TokensRefreshedAt is the time when the tokens within the session was refreshed.
	TokensRefreshedAt time.Time `json:"tokens_refreshed_at"`
}

func NewMetadata(expiresIn time.Duration, endsIn time.Duration) *Metadata {
	now := time.Now()
	return &Metadata{
		SessionCreatedAt:  now,
		SessionEndsAt:     now.Add(endsIn),
		TokensRefreshedAt: now,
		TokensExpireAt:    now.Add(expiresIn),
	}
}

func (in *Metadata) NextRefresh() time.Time {
	// subtract the leeway to ensure that we refresh before expiry
	next := in.TokensExpireAt.Add(-RefreshLeeway)

	// try to refresh at the first opportunity if the next refresh is in the past
	if next.Before(time.Now()) {
		return in.RefreshCooldown()
	}

	return next
}

func (in *Metadata) Refresh(nextExpirySeconds int64) {
	now := time.Now()
	in.TokensRefreshedAt = now
	in.TokensExpireAt = now.Add(time.Duration(nextExpirySeconds) * time.Second)
}

func (in *Metadata) RefreshCooldown() time.Time {
	refreshed := in.TokensRefreshedAt
	tokenLifetime := in.TokenLifetime()

	// if token lifetime is less than the minimum refresh interval * 2, we'll allow refreshes at the token half-life
	if tokenLifetime <= RefreshMinInterval*2 {
		return refreshed.Add(tokenLifetime / 2)
	}

	return refreshed.Add(RefreshMinInterval)
}

func (in *Metadata) RefreshOnCooldown() bool {
	return time.Now().Before(in.RefreshCooldown())
}

func (in *Metadata) ShouldRefresh() bool {
	if in.RefreshOnCooldown() {
		return false
	}

	return time.Now().After(in.NextRefresh())
}

func (in *Metadata) TokenLifetime() time.Duration {
	return in.TokensExpireAt.Sub(in.TokensRefreshedAt)
}

func (in *Metadata) Verbose() MetadataVerbose {
	now := time.Now()

	expireTime := in.TokensExpireAt
	endTime := in.SessionEndsAt
	nextRefreshTime := in.NextRefresh()

	return MetadataVerbose{
		Metadata:                     *in,
		SessionEndsInSeconds:         toSeconds(endTime.Sub(now)),
		TokensExpireInSeconds:        toSeconds(expireTime.Sub(now)),
		TokensNextRefreshInSeconds:   toSeconds(nextRefreshTime.Sub(now)),
		TokensRefreshCooldown:        in.RefreshOnCooldown(),
		TokensRefreshCooldownSeconds: toSeconds(in.RefreshCooldown().Sub(now)),
	}
}

type MetadataVerbose struct {
	Metadata
	SessionEndsInSeconds         int64 `json:"session_ends_in_seconds"`
	TokensExpireInSeconds        int64 `json:"tokens_expire_in_seconds"`
	TokensNextRefreshInSeconds   int64 `json:"tokens_next_refresh_in_seconds"`
	TokensRefreshCooldown        bool  `json:"tokens_refresh_cooldown"`
	TokensRefreshCooldownSeconds int64 `json:"tokens_refresh_cooldown_seconds"`
}

func toSeconds(d time.Duration) int64 {
	i := int64(d.Seconds())
	if i <= 0 {
		return 0
	}

	return i
}
