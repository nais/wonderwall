package session

import (
	"encoding"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	RefreshMinInterval = 1 * time.Minute
	RefreshLeeway      = 5 * time.Minute
)

type EncryptedData struct {
	Ciphertext []byte
}

var (
	_ encoding.BinaryMarshaler   = &EncryptedData{}
	_ encoding.BinaryUnmarshaler = &EncryptedData{}
)

func (in *EncryptedData) MarshalBinary() ([]byte, error) {
	return in.Ciphertext, nil
}

func (in *EncryptedData) UnmarshalBinary(bytes []byte) error {
	in.Ciphertext = bytes
	return nil
}

func (in *EncryptedData) Decrypt(crypter crypto.Crypter) (*Data, error) {
	rawData, err := crypter.Decrypt(in.Ciphertext)
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
	Acr               string   `json:"acr"`
	Metadata          Metadata `json:"metadata"`
}

func NewData(externalSessionID string, tokens *openid.Tokens, metadata *Metadata) *Data {
	data := &Data{
		ExternalSessionID: externalSessionID,
		AccessToken:       tokens.AccessToken,
		IDToken:           tokens.IDToken.Serialized(),
		RefreshToken:      tokens.RefreshToken,
		Acr:               tokens.IDToken.Acr(),
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
		Ciphertext: ciphertext,
	}, nil
}

func (in *Data) HasAccessToken() bool {
	return len(in.AccessToken) > 0
}

func (in *Data) HasActiveAccessToken() bool {
	return in.HasAccessToken() && !in.Metadata.IsExpired()
}

func (in *Data) HasRefreshToken() bool {
	return len(in.RefreshToken) > 0
}

func (in *Data) Validate() error {
	if !in.HasAccessToken() {
		return fmt.Errorf("%w: no access token in data", ErrInvalid)
	}

	if in.Metadata.IsEnded() {
		return fmt.Errorf("%w: has ended", ErrInvalid)
	}

	if in.Metadata.IsTimedOut() {
		return fmt.Errorf("%w: %w", ErrInvalid, ErrInactive)
	}

	return nil
}

type Metadata struct {
	Session MetadataSession `json:"session"`
	Tokens  MetadataTokens  `json:"tokens"`
}

type MetadataSession struct {
	// CreatedAt is the time when the session was created.
	CreatedAt time.Time `json:"created_at"`
	// EndsAt is the time when the session will end, i.e. the absolute lifetime/time-to-live for the session.
	EndsAt time.Time `json:"ends_at"`
	// TimeoutAt is the time when the session will be marked as inactive. A zero value means no timeout. The timeout is extended whenever the tokens are refreshed.
	TimeoutAt time.Time `json:"timeout_at"`
}

type MetadataTokens struct {
	// ExpireAt is the time when the tokens will expire.
	ExpireAt time.Time `json:"expire_at"`
	// RefreshedAt is the time when the tokens were last refreshed.
	RefreshedAt time.Time `json:"refreshed_at"`
}

func NewMetadata(expiresIn, endsIn time.Duration) *Metadata {
	now := time.Now()
	return &Metadata{
		Session: MetadataSession{
			CreatedAt: now,
			EndsAt:    now.Add(endsIn),
		},
		Tokens: MetadataTokens{
			ExpireAt:    now.Add(expiresIn),
			RefreshedAt: now,
		},
	}
}

func (in *Metadata) IsEnded() bool {
	return time.Now().After(in.Session.EndsAt)
}

func (in *Metadata) IsExpired() bool {
	return time.Now().After(in.Tokens.ExpireAt)
}

func (in *Metadata) IsRefreshOnCooldown() bool {
	return time.Now().Before(in.RefreshCooldown())
}

func (in *Metadata) NextRefresh() time.Time {
	// subtract the leeway to ensure that we refresh before expiry
	next := in.Tokens.ExpireAt.Add(-RefreshLeeway)

	// if inactivity is enabled...
	timeout := in.Session.TimeoutAt
	if !timeout.IsZero() {
		// ...refresh at the half-life between the last refresh and the timeout
		lastRefresh := in.Tokens.RefreshedAt
		halfLife := lastRefresh.Add(timeout.Sub(lastRefresh) / 2)

		if halfLife.Before(next) {
			next = halfLife
		}
	}

	// try to refresh at the first opportunity if the next refresh is in the past
	if next.Before(time.Now()) {
		return in.RefreshCooldown()
	}

	return next
}

func (in *Metadata) Refresh(nextExpirySeconds int64) {
	now := time.Now()
	in.Tokens.RefreshedAt = now
	in.Tokens.ExpireAt = now.Add(time.Duration(nextExpirySeconds) * time.Second)
}

func (in *Metadata) RefreshCooldown() time.Time {
	refreshed := in.Tokens.RefreshedAt
	tokenLifetime := in.TokenLifetime()

	// if token lifetime is less than the minimum refresh interval * 2, we'll allow refreshes at the token half-life
	if tokenLifetime <= RefreshMinInterval*2 {
		return refreshed.Add(tokenLifetime / 2)
	}

	return refreshed.Add(RefreshMinInterval)
}

func (in *Metadata) ShouldRefresh() bool {
	if in.IsExpired() {
		return true
	}

	if in.IsRefreshOnCooldown() {
		return false
	}

	return time.Now().After(in.NextRefresh())
}

func (in *Metadata) TokenLifetime() time.Duration {
	return in.Tokens.ExpireAt.Sub(in.Tokens.RefreshedAt)
}

func (in *Metadata) IsTimedOut() bool {
	if in.Session.TimeoutAt.IsZero() {
		return false
	}

	return time.Now().After(in.Session.TimeoutAt)
}

func (in *Metadata) WithTimeout(timeoutIn time.Duration) {
	timeoutAt := time.Now().Add(timeoutIn)
	in.Session.TimeoutAt = timeoutAt

	if timeoutAt.Before(in.Tokens.ExpireAt) {
		in.Tokens.ExpireAt = timeoutAt
	}
}

func (in *Metadata) Verbose() MetadataVerbose {
	now := time.Now()

	expireTime := in.Tokens.ExpireAt
	endTime := in.Session.EndsAt
	timeoutTime := in.Session.TimeoutAt

	session := MetadataSessionVerbose{
		MetadataSession:  in.Session,
		EndsInSeconds:    toSeconds(endTime.Sub(now)),
		Active:           !in.IsTimedOut(),
		TimeoutInSeconds: toSeconds(timeoutTime.Sub(now)),
	}
	if timeoutTime.IsZero() {
		session.TimeoutInSeconds = int64(-1)
	}

	tokens := MetadataTokensVerbose{
		MetadataTokens:           in.Tokens,
		ExpireInSeconds:          toSeconds(expireTime.Sub(now)),
		NextAutoRefreshInSeconds: toSeconds(in.NextRefresh().Sub(now)),
		RefreshCooldown:          in.IsRefreshOnCooldown(),
		RefreshCooldownSeconds:   toSeconds(in.RefreshCooldown().Sub(now)),
	}

	return MetadataVerbose{
		Session: session,
		Tokens:  tokens,
	}
}

func (in *Metadata) SetSpanAttributes(span trace.Span) {
	span.SetAttributes(attribute.String("session.token_expires_at", in.Tokens.ExpireAt.Format(time.RFC3339)))
	span.SetAttributes(attribute.String("session.token_refreshed_at", in.Tokens.RefreshedAt.Format(time.RFC3339)))
	span.SetAttributes(attribute.String("session.created_at", in.Session.CreatedAt.Format(time.RFC3339)))
	span.SetAttributes(attribute.String("session.ends_at", in.Session.EndsAt.Format(time.RFC3339)))
	if !in.Session.TimeoutAt.IsZero() {
		span.SetAttributes(attribute.String("session.timeout_at", in.Session.TimeoutAt.Format(time.RFC3339)))
	}
}

type MetadataVerbose struct {
	Session MetadataSessionVerbose `json:"session"`
	Tokens  MetadataTokensVerbose  `json:"tokens"`
}

type MetadataSessionVerbose struct {
	MetadataSession
	EndsInSeconds    int64 `json:"ends_in_seconds"`
	Active           bool  `json:"active"`
	TimeoutInSeconds int64 `json:"timeout_in_seconds"`
}

type MetadataTokensVerbose struct {
	MetadataTokens
	ExpireInSeconds          int64 `json:"expire_in_seconds"`
	NextAutoRefreshInSeconds int64 `json:"next_auto_refresh_in_seconds"`
	RefreshCooldown          bool  `json:"refresh_cooldown"`
	RefreshCooldownSeconds   int64 `json:"refresh_cooldown_seconds"`
}

func toSeconds(d time.Duration) int64 {
	i := int64(d.Seconds())
	if i <= 0 {
		return 0
	}

	return i
}
