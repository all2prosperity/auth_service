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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Configure properly for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ConnectRPC preflight/CORS helper for JSON/Connect transport
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Connect-Protocol-Version, Connect-Timeout-Ms")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

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

	// Create HTTP server (h2c enables HTTP/2 cleartext for ConnectRPC)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
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
