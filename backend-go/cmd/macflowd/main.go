// Package main is the entry point for the MACFlow backend.
// MACFlow is a traffic splitting system for iStoreOS/OpenWrt routers.
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"macflow/internal/api"
	"macflow/internal/config"
	"macflow/internal/health"
	"macflow/internal/runtime"
	"macflow/internal/state"
)

// Version is injected at build time via -ldflags "-X main.Version=x.y.z".
// Falls back to "dev" when not set (local builds).
var Version = "dev"

func main() {
	cfg := config.Load()
	cfg.Version = Version

	// Initialize state store
	store, err := state.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("failed to init state store: %v", err)
	}

	// Initialize health monitor
	monitor := health.NewMonitor()

	// Build HTTP router
	router := api.NewRouter(cfg, store, monitor)

	listenAddr := cfg.BindAddr + ":" + strconv.Itoa(cfg.ListenPort)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start background tasks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create runtime manager for background tasks
	rtMgr := runtime.NewManager(store)

	// Auto-apply policy on startup (load nftables, singbox config, ip rules)
	go func() {
		time.Sleep(3 * time.Second)
		st := store.Read()
		if st.Enabled {
			log.Println("auto-applying policy on startup...")
			result := rtMgr.HotApply(false)
			log.Printf("auto-apply result: singbox=%s nftables=%s ip_rules=%s",
				result.Singbox, result.Nftables, result.IPRules)
		}
	}()

	go monitor.RunProbeLoopWithRT(ctx, store, cfg, rtMgr)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	// Listen on tcp4 explicitly to ensure IPv4 access on systems with bindv6only=1
	log.Printf("macflowd v%s listening on %s", Version, listenAddr)
	ln, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
