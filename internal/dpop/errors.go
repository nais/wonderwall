package dpop

import (
	"errors"

	"golang.org/x/oauth2"
)

var ErrUseNonce = errors.New("authorization server requires a DPoP nonce")

// ErrorCodeUseNonce signals that the server requires a nonce in the next proof.
const ErrorCodeUseNonce = "use_dpop_nonce"

// IsNonceChallenge reports whether err is a nonce challenge from the authorization server.
// It accepts both errors wrapping ErrUseNonce and the error type returned by oauth2.Config.Exchange.
func IsNonceChallenge(err error) bool {
	if errors.Is(err, ErrUseNonce) {
		return true
	}
	retrieveError, ok := errors.AsType[*oauth2.RetrieveError](err)
	return ok && retrieveError.ErrorCode == ErrorCodeUseNonce && retrieveError.Response != nil && retrieveError.Response.Header.Get("DPoP-Nonce") != ""
}
