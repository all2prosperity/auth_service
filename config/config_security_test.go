package config

import "testing"

func baseProdConfig() *Config {
	c := &Config{AppEnv: "production"}
	c.Database.Host = "localhost"
	c.Database.Port = 5432
	c.Database.User = "postgres"
	c.Database.DBName = "auth"
	c.Server.Port = 8080
	c.JWT.AccessSecret = "a-sufficiently-long-access-secret-value!!"
	c.JWT.RefreshSecret = "a-sufficiently-long-refresh-secret-value!"
	c.Security.AllowedOrigins = []string{"https://app.example.com"}
	return c
}

func TestValidate_ProductionRejectsDefaultSecret(t *testing.T) {
	c := baseProdConfig()
	c.JWT.AccessSecret = "change-me-access-secret"
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation to fail for default JWT secret in production")
	}
}

func TestValidate_ProductionRejectsShortSecret(t *testing.T) {
	c := baseProdConfig()
	c.JWT.AccessSecret = "too-short"
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation to fail for short JWT secret in production")
	}
}

func TestValidate_ProductionRejectsWildcardCORS(t *testing.T) {
	c := baseProdConfig()
	c.Security.AllowedOrigins = []string{"*"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation to fail for wildcard CORS origin in production")
	}
}

func TestValidate_ProductionRejectsEnabledTestBypass(t *testing.T) {
	c := baseProdConfig()
	c.Security.EnableTestBypass = true
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation to fail when test bypass is enabled in production")
	}
}

func TestValidate_ProductionAcceptsStrongConfig(t *testing.T) {
	if err := baseProdConfig().Validate(); err != nil {
		t.Fatalf("expected strong production config to validate, got: %v", err)
	}
}

func TestValidate_DevelopmentAllowsDefaults(t *testing.T) {
	c := baseProdConfig()
	c.AppEnv = "development"
	c.JWT.AccessSecret = "change-me-access-secret"
	c.JWT.RefreshSecret = "change-me-refresh-secret"
	c.Security.AllowedOrigins = []string{"*"}
	c.Security.EnableTestBypass = true
	if err := c.Validate(); err != nil {
		t.Fatalf("expected development config to validate, got: %v", err)
	}
}
