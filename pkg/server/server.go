package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
)

var (
	defaultTransport *http.Transport
	once             sync.Once
)

func DefaultTransport() *http.Transport {
	once.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 200
		t.MaxIdleConnsPerHost = 100
		t.IdleConnTimeout = 5 * time.Second

		defaultTransport = t
	})

	return defaultTransport
}

func Start(cfg *config.Config, r chi.Router) error {
	server := http.Server{
		Addr:    cfg.BindAddress,
		Handler: r,
	}

	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		s := <-sig
		log.Infof("server: received %q; waiting for %s before starting graceful shutdown...", s, cfg.ShutdownWaitBeforePeriod)
		time.Sleep(cfg.ShutdownWaitBeforePeriod)

		// the total terminationGracePeriodSeconds in Kubernetes starts immediately when SIGTERM is sent, so we need to subtract the wait-before period to exit before SIGKILL
		shutdownTimeout := cfg.ShutdownGracefulPeriod - cfg.ShutdownWaitBeforePeriod
		shutdownCtx, shutdownStopCtx := context.WithTimeout(serverCtx, shutdownTimeout)

		go func() {
			<-shutdownCtx.Done()
			if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
				log.Fatalf("server: graceful shutdown timed out after %s; forcing exit.", shutdownTimeout)
			}
		}()

		log.Infof("server: starting graceful shutdown (will timeout after %s)...", shutdownTimeout)
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		shutdownStopCtx()
		serverStopCtx()
	}()

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	<-serverCtx.Done()
	log.Infof("server: shutdown completed")
	return nil
}
