package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// jitaccess-authorizer — a single static binary that gates any proxy able to
// make a forward-auth subrequest (NGINX auth_request, Traefik forwardAuth,
// Caddy forward_auth, Envoy ext_authz).
//
// Simple profile: all state is in-process. No Redis, no database.

var version = "0.1.0"

func main() {
	var (
		cfgPath  = flag.String("config", "config.json", "path to the JSON config file")
		check    = flag.Bool("check", false, "validate the config and exit")
		showVer  = flag.Bool("version", false, "print version and exit")
		listenOv = flag.String("listen", "", "override listen address")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("jitaccess-authorizer", version)
		return
	}

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listenOv != "" {
		cfg.Listen = *listenOv
	}
	if *check {
		fmt.Printf("config OK: %d token(s), %d service(s), listen %s\n",
			len(cfg.Tokens), len(cfg.Services), cfg.Listen)
		return
	}

	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}

	stop := make(chan struct{})
	srv.StartSweeper(stop)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// SIGHUP reloads the config (token registry + services) without dropping
	// live grants; they are re-checked against the new registry on next use.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			switch s {
			case syscall.SIGHUP:
				nc, err := LoadConfig(*cfgPath)
				if err != nil {
					logf("reload failed, keeping previous config: %v", err)
					continue
				}
				if err := srv.Reload(nc); err != nil {
					logf("reload failed, keeping previous config: %v", err)
					continue
				}
				logf("reloaded: %d token(s), %d service(s)", len(nc.Tokens), len(nc.Services))
			default:
				logf("shutting down")
				close(stop)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = httpSrv.Shutdown(ctx)
				cancel()
				return
			}
		}
	}()

	logf("jitaccess-authorizer %s listening on %s (prefix %s, %d service(s), %d token(s))",
		version, cfg.Listen, cfg.URIPrefix, len(cfg.Services), len(cfg.Tokens))
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}
