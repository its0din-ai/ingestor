package main

import (
	"html/template"
	"log/slog"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/encrypt0r/ingestor/internal/admin"
	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/upload"
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
	uploadHandler := upload.New(cfg, conn, auditLog)
	adminHandler := admin.New(cfg, conn, tmpl, auditLog)

	mux := http.NewServeMux()

	// root: GET redirects to login/dashboard; other methods are the
	// bearer-protected upload sink (accept-and-log-everything).
	rootRedirect := auth.Root(conn)
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
	mux.Handle("/login", auth.Public(conn)(publicMux))
	mux.Handle("/logout", auth.Public(conn)(publicMux))

	// dashboard (session protected)
	dashMux := http.NewServeMux()
	dashMux.HandleFunc("GET /dashboard/", adminHandler.Dashboard)
	dashMux.HandleFunc("GET /dashboard", adminHandler.Dashboard)
	dashMux.HandleFunc("GET /dashboard/api/files", adminHandler.ListFiles)
	dashMux.HandleFunc("GET /dashboard/download", adminHandler.Download)
	dashMux.HandleFunc("POST /dashboard/delete", adminHandler.Delete)
	dashMux.HandleFunc("GET /dashboard/api/settings", adminHandler.SettingsJSON)
	dashMux.HandleFunc("POST /dashboard/api/settings", adminHandler.SaveSettingsJSON)
	dashMux.HandleFunc("GET /dashboard/api/audit", adminHandler.ListAudit)
	mux.Handle("/dashboard/", auth.Admin(conn)(dashMux))

	// upload API (bearer protected)
	mux.Handle("/upload", auth.Bearer(cfg, auditLog)(uploadHandler))

	addr := cfg.Addr()
	slog.Info("ingestor listening", "addr", addr)

	if err := http.ListenAndServe(addr, logging.Middleware(mux)); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
