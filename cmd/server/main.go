package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auth "github.com/all2prosperity/auth_service/auth"
	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/internal/logger"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Load configuration first
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize logger manager
	loggerConfig := cfg.Logging.ToLoggerConfig()
	loggerManager, err := logger.NewManager(loggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer loggerManager.Close()

	// Get unified logger
	appLogger := loggerManager.GetUnifiedLogger()

	// Print configuration for debugging
	cfg.Print()
	appLogger.Info("Starting Auth Service...")

	// Initialize auth module
	authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
		Config:         cfg,
		LoggerManager:  loggerManager,
		ConsoleEnabled: os.Getenv("CONSOLE_ENABLED") != "false",
	})
	if err != nil {
		appLogger.Error("Failed to initialize auth module", logger.Err("error", err))
		os.Exit(1)
	}
	defer authModule.Close()

	appLogger.Info("Auth module initialized successfully")

	// Start cleanup routine
	authModule.StartCleanupRoutine()

	// Setup HTTP server
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	// Global per-IP rate limiting (Redis-backed; no-op if disabled/unavailable).
	router.Use(authModule.IPRateLimitMiddleware())
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS — origins are read from configuration. Production must not use "*"
	// (enforced by config.Validate).
	allowedOrigins := cfg.Security.AllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "Connect-Protocol-Version", "Connect-Timeout-Ms"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := authModule.Health(); err != nil {
			http.Error(w, fmt.Sprintf("Auth module unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	// OpenAPI specification (for third-party client generation)
	router.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api/openapi.yaml")
	})

	// Register auth service routes
	authModule.RegisterRoutes(router)

	// Console routes (if enabled)
	consoleMux := http.NewServeMux()
	authModule.RegisterConsoleRoutes(consoleMux)
	router.Mount("/admin", consoleMux)

	// Additional routes for testing
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		status := "Auth Service v0.4 - Running on port " + fmt.Sprintf("%d", cfg.Server.Port)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, status)
	})

	// Create HTTP server (plain HTTP/1.1; REST/JSON needs no h2c).
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	fmt.Println("Server starting on port", cfg.Server.Port)

	// Start server in a goroutine
	go func() {
		appLogger.Info("Server starting on port", logger.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Server failed to start", logger.Err("error", err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Error("Server forced to shutdown", logger.Err("error", err))
	}

	appLogger.Info("Server exited")
}
