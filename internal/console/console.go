package console

import (
	"fmt"
	"log"
	"net/http"

	"auth_service/internal/console/handler"
	"auth_service/internal/console/metrics"
	"auth_service/internal/console/rbac"
	"auth_service/internal/console/service"
	"auth_service/internal/console/store"

	"gorm.io/gorm"
)

// Console represents the console module
type Console struct {
	handler *handler.ConsoleHandler
	metrics *metrics.Metrics
	store   store.Store
	service *service.ConsoleService
}

// Config holds console configuration
type Config struct {
	JWTSecret string
	Enabled   bool
}

// NewConsole creates and initializes the console module
func NewConsole(db *gorm.DB, config Config) (*Console, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("console module is disabled")
	}

	// Initialize metrics
	consoleMetrics := metrics.NewMetrics()

	// Initialize RBAC guard
	rbacGuard := rbac.NewGuard()

	// Initialize store (database implementation for integrated mode)
	consoleStore := store.NewDBStore(db)

	// Initialize service
	consoleService := service.NewConsoleService(consoleStore, rbacGuard, consoleMetrics)

	// Initialize handler
	consoleHandler := handler.NewConsoleHandler(consoleService, config.JWTSecret)

	return &Console{
		handler: consoleHandler,
		metrics: consoleMetrics,
		store:   consoleStore,
		service: consoleService,
	}, nil
}

// RegisterRoutes registers console routes with the provided router
func (c *Console) RegisterRoutes(mux *http.ServeMux) {
	if c.handler == nil {
		return
	}

	log.Println("[CONSOLE] Registering console routes...")
	c.handler.SetupRoutes(mux)
	log.Println("[CONSOLE] Console routes registered successfully")
}

// GetMetrics returns console metrics for monitoring
func (c *Console) GetMetrics() *metrics.Metrics {
	return c.metrics
}

// GetHandler returns the console handler
func (c *Console) GetHandler() *handler.ConsoleHandler {
	return c.handler
}

// Health checks the health of console components
func (c *Console) Health() error {
	// Check store health
	if err := c.store.Health(nil); err != nil {
		return fmt.Errorf("console store health check failed: %w", err)
	}

	return nil
}
