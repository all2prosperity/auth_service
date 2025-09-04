package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_service/config"
	"auth_service/database"
	"auth_service/internal/console"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	var (
		port       = flag.Int("port", 8081, "Port to run console service on")
		configFile = flag.String("config", ".env", "Configuration file path")
	)
	flag.Parse()

	// Load environment variables
	if err := godotenv.Load(*configFile); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Setup logger
	logger := zap.L().Sugar()
	logger.Info("Starting Console Service in standalone mode...")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", zap.Error(err))
	}

	// Initialize database
	db, err := database.NewDatabase(&cfg.Database, logger)
	if err != nil {
		logger.Error("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		logger.Error("Failed to run migrations", zap.Error(err))
	}

	logger.Info("Database connected and migrations completed")

	// Initialize console module
	consoleConfig := console.Config{
		JWTSecret: cfg.JWT.AccessSecret,
		Enabled:   true,
	}

	consoleModule, err := console.NewConsole(db.DB, consoleConfig)
	if err != nil {
		logger.Error("Failed to initialize console module", zap.Error(err))
	}

	// Setup HTTP server
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
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

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := consoleModule.Health(); err != nil {
			http.Error(w, fmt.Sprintf("Console unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	// Console routes
	mux := http.NewServeMux()
	consoleModule.RegisterRoutes(mux)

	// Mount console routes
	router.Mount("/", mux)

	// Root endpoint
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Console Service v1.0 - Running in standalone mode on port %d", *port)
	})

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Console service starting on port %d", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", zap.Error(err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down console service...")

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Console service forced to shutdown", zap.Error(err))
	}

	logger.Info("Console service exited")
}
