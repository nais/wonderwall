package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nais/wonderwall/pkg/config"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
)

type SessionSource interface {
	GetSessions() *session.Handler
	GetSessionConfig() config.Session
}

func Session(src SessionSource, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	ticket, err := src.GetSessions().GetTicket(r)
	if err != nil {
		logger.Infof("session/refresh: getting ticket: %+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data, err := src.GetSessions().Get(r, ticket)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrInvalidSession), errors.Is(err, session.ErrKeyNotFound):
			logger.Infof("session/info: getting session: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			logger.Warnf("session/info: getting session: %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if src.GetSessionConfig().Refresh {
		err = json.NewEncoder(w).Encode(data.Metadata.VerboseWithRefresh())
	} else {
		err = json.NewEncoder(w).Encode(data.Metadata.Verbose())
	}

	if err != nil {
		logger.Warnf("session/info: marshalling metadata: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
