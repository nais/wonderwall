package handler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
)

func TestHandler_Error(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	handler := idp.RelyingPartyHandler

	for _, test := range []struct {
		name               string
		expectedStatusCode int
		fn                 func(w http.ResponseWriter, r *http.Request, cause error)
	}{
		{
			name:               "bad request",
			expectedStatusCode: http.StatusBadRequest,
			fn:                 handler.BadRequest,
		},
		{
			name:               "internal error",
			expectedStatusCode: http.StatusInternalServerError,
			fn:                 handler.InternalError,
		},
		{
			name:               "unauthorized",
			expectedStatusCode: http.StatusUnauthorized,
			fn:                 handler.Unauthorized,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, idp.RelyingPartyServer.URL, nil)
			w := httptest.NewRecorder()

			test.fn(w, r, fmt.Errorf("some error"))
			assert.Equal(t, test.expectedStatusCode, w.Result().StatusCode)
		})
	}
}
