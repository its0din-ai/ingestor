package main

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/encrypt0r/ingestor/internal/admin"
	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/upload"
	"github.com/encrypt0r/ingestor/internal/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := godotenv.Load(); err != nil {
		slog.Warn("no .env file found, using existing environment", "err", err)
	}

	conn, err := db.Open(os.Getenv("db_path"))
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	cfg, err := config.Load(conn)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		slog.Error("failed to parse templates", "err", err)
		os.Exit(1)
	}

	auditLog := audit.New(conn)
	sessions, err := auth.NewManager(cfg, conn)
	if err != nil {
		slog.Error("failed to initialize auth", "err", err)
		os.Exit(1)
	}
	uploadHandler := upload.New(cfg, conn, auditLog)
	adminHandler := admin.New(cfg, conn, sessions, tmpl, auditLog)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "healthy"})
	})

	// root: GET redirects to login/dashboard; other methods are the
	// bearer-protected upload sink (accept-and-log-everything).
	rootRedirect := sessions.Root()
	bearerUpload := auth.Bearer(cfg, auditLog)(uploadHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rootRedirect(w, r)
			return
		}
		bearerUpload.ServeHTTP(w, r)
	})

	// public login/logout
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /login", adminHandler.LoginForm)
	publicMux.HandleFunc("POST /login", adminHandler.Login)
	publicMux.HandleFunc("POST /logout", adminHandler.Logout)
	mux.Handle("/login", sessions.Public()(publicMux))
	mux.Handle("/logout", sessions.Public()(publicMux))

	// dashboard (session protected)
	dashMux := http.NewServeMux()
	dashMux.HandleFunc("GET /dashboard/", adminHandler.Dashboard)
	dashMux.HandleFunc("GET /dashboard", adminHandler.Dashboard)
	dashMux.HandleFunc("GET /dashboard/api/files", adminHandler.ListFiles)
	dashMux.HandleFunc("GET /dashboard/api/disk", adminHandler.DiskUsage)
	dashMux.HandleFunc("GET /dashboard/download", adminHandler.Download)
	dashMux.HandleFunc("GET /dashboard/read", adminHandler.Read)
	dashMux.HandleFunc("POST /dashboard/delete", adminHandler.Delete)
	dashMux.HandleFunc("POST /dashboard/quarantine", adminHandler.Quarantine)
	dashMux.HandleFunc("POST /dashboard/release", adminHandler.Release)
	dashMux.Handle("POST /dashboard/upload", uploadHandler)
	dashMux.HandleFunc("GET /dashboard/api/settings", adminHandler.SettingsJSON)
	dashMux.HandleFunc("POST /dashboard/api/settings", adminHandler.SaveSettingsJSON)
	dashMux.HandleFunc("GET /dashboard/api/audit", adminHandler.ListAudit)
	mux.Handle("/dashboard/", sessions.Admin()(dashMux))

	// upload API (bearer protected)
	mux.Handle("/upload", auth.Bearer(cfg, auditLog)(uploadHandler))

	addr := cfg.Addr()
	writeTimeout := cfg.WriteTimeout()
	srv := &http.Server{
		Addr:              addr,
		Handler:           logging.Middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		WriteTimeout:      writeTimeout,
		MaxHeaderBytes:    1 << 20,
	}
	slog.Info("ingestor listening", "addr", addr, "write_timeout", writeTimeout.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Hourly maintenance: prune expired sessions and, if configured, audit
	// entries older than the retention window.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if err := db.DeleteExpiredSessions(conn, now); err != nil {
					slog.Warn("failed to prune expired sessions", "err", err)
				}
				if ret := cfg.AuditRetention(); ret > 0 {
					if err := db.DeleteAuditOlderThan(conn, now.Add(-ret)); err != nil {
						slog.Warn("failed to prune audit log", "err", err)
					}
				}
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "err", err)
		}
		slog.Info("server stopped")
	}
}
