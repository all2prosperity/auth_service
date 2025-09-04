package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/migrations"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	var (
		action = flag.String("action", "up", "Migration action: up, down, seed, status")
		env    = flag.String("env", ".env", "Environment file path")
	)
	flag.Parse()

	// Load environment variables
	if err := godotenv.Load(*env); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	db, err := database.NewDatabase(&cfg.Database, zap.L().Sugar())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Get underlying GORM DB for migrations
	gormDB := db.DB

	// Create migration manager
	migrator := migrations.NewMigrationManager(gormDB)

	// Execute migration action
	switch *action {
	case "up":
		fmt.Println("Running migrations...")
		if err := migrator.RunMigrations(); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
		fmt.Println("Migrations completed successfully!")

	case "down":
		fmt.Println("Rolling back migrations...")
		if err := migrator.RollbackMigrations(); err != nil {
			log.Fatalf("Failed to rollback migrations: %v", err)
		}
		fmt.Println("Migrations rolled back successfully!")

	case "seed":
		fmt.Println("Seeding data...")
		if err := migrator.SeedData(); err != nil {
			log.Fatalf("Failed to seed data: %v", err)
		}
		fmt.Println("Data seeded successfully!")

	case "status":
		fmt.Println("Checking migration status...")
		if err := migrator.CheckHealth(); err != nil {
			log.Fatalf("Migration check failed: %v", err)
		}
		fmt.Println("All migrations are up to date!")

	default:
		fmt.Printf("Unknown action: %s\n", *action)
		fmt.Println("Available actions: up, down, seed, status")
		os.Exit(1)
	}
}
