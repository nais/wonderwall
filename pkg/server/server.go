package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/metrics"
)

func Start(ctx context.Context, cfg *config.Config, r chi.Router) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	mainServer := &http.Server{
		Addr:              cfg.BindAddress,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second, // Prevents slowloris attacks (connections held open without sending headers).
		IdleTimeout:       90 * time.Second, // Reclaims idle keep-alive connections; without this, goroutines and buffers leak indefinitely.
		MaxHeaderBytes:    1 << 16,          // 64KB
		// ReadTimeout/WriteTimeout intentionally omitted - a reverse proxy must support slow transfers.
	}

	servers := []*http.Server{mainServer}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		log.Infof("server: listening on %s", cfg.BindAddress)
		if err := mainServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: %w", err)
		}
		return nil
	})

	if cfg.MetricsBindAddress != "" {
		metricsServer := newMetricsServer(cfg)
		servers = append(servers, metricsServer)

		g.Go(func() error {
			log.Debugf("metrics: listening on %s", cfg.MetricsBindAddress)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("metrics: %w", err)
			}
			return nil
		})
	}

	if cfg.ProbeBindAddress != "" {
		probeServer := newProbeServer(cfg)
		servers = append(servers, probeServer)

		g.Go(func() error {
			log.Debugf("probe: listening on %s", cfg.ProbeBindAddress)
			if err := probeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("probe: %w", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		<-gctx.Done()

		log.Infof("server: received shutdown signal; waiting for %s before starting graceful shutdown...", cfg.ShutdownWaitBeforePeriod)
		time.Sleep(cfg.ShutdownWaitBeforePeriod)

		// the total terminationGracePeriodSeconds in Kubernetes starts immediately when SIGTERM is sent,
		// so we need to subtract the wait-before period to exit before SIGKILL
		shutdownTimeout := cfg.ShutdownGracefulPeriod - cfg.ShutdownWaitBeforePeriod
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		log.Infof("server: starting graceful shutdown (will timeout after %s)...", shutdownTimeout)

		var errs []error
		for _, srv := range servers {
			if err := srv.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, err)
			}
		}

		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}

		log.Infof("server: shutdown completed")
		return nil
	})

	return g.Wait()
}

func newMetricsServer(cfg *config.Config) *http.Server {
	metrics.WithProvider(string(cfg.OpenID.Provider))
	metrics.Register()
	metrics.InitLabels()

	return &http.Server{
		Addr:              cfg.MetricsBindAddress,
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func newProbeServer(cfg *config.Config) *http.Server {
	mux := http.NewServeMux()
	healthz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", healthz)
	mux.HandleFunc("/healthz", healthz)

	if cfg.PprofEnabled {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		log.Infof("pprof: enabled on %s/debug/pprof/", cfg.ProbeBindAddress)
	}

	return &http.Server{
		Addr:              cfg.ProbeBindAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}
