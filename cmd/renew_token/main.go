package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"auth_service/config"
	"auth_service/dao"
	"auth_service/database"
	"auth_service/services"

	"go.uber.org/zap"
)

type output struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email,omitempty"`
	PhoneNumber  string `json:"phone_number,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccessTTL    string `json:"access_token_ttl"`
	RefreshTTL   string `json:"refresh_token_ttl"`
	RenewedAt    string `json:"renewed_at"`
}

func main() {
	// Flags
	email := flag.String("email", "", "用户邮箱，可选，与 --phone 二选一")
	phone := flag.String("phone", "", "用户手机号，可选，与 --email 二选一")
	password := flag.String("password", "", "用户密码，用于身份验证")
	configFile := flag.String("config", "", "可选，自定义配置文件路径（覆盖内置查找顺序）")
	jsonOut := flag.Bool("json", true, "是否以 JSON 输出，默认 true")
	skipAuth := flag.Bool("skip-auth", false, "跳过密码验证（仅用于管理员操作）")
	flag.Parse()

	if *email == "" && *phone == "" {
		log.Fatal("必须提供 --email 或 --phone 其中之一")
	}

	if !*skipAuth && *password == "" {
		log.Fatal("必须提供 --password 进行身份验证，或使用 --skip-auth 跳过验证")
	}

	// Logger
	zl, _ := zap.NewProduction()
	defer zl.Sync()
	sugar := zl.Sugar()

	// Load config
	var (
		cfg *config.Config
		err error
	)
	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
	} else {
		cfg, err = config.LoadConfig()
	}
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// Init DB and migrate
	db, err := database.NewDatabase(&cfg.Database, sugar)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}
	defer db.Close()

	if err := db.AutoMigrate(); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	// Prepare services/dao
	userDAO := dao.NewUserDAO(db)
	passwordService := services.NewPasswordService()
	jwtService := services.NewJWTService(&cfg.JWT, db)

	// Get user by identifier
	var identifier string
	if *email != "" {
		identifier = *email
	} else {
		identifier = *phone
	}

	user, err := userDAO.GetUserByIdentifier(identifier)
	if err != nil {
		log.Fatalf("用户不存在: %s", identifier)
	}

	// Check if user is locked
	if user.IsLocked() {
		log.Fatalf("用户账号已被锁定")
	}

	// Verify password if not skipping auth
	if !*skipAuth {
		if user.PasswordHash == nil {
			log.Fatalf("该用户未设置密码，无法验证身份")
		}

		valid, err := passwordService.VerifyPassword(*password, *user.PasswordHash)
		if err != nil {
			log.Fatalf("密码验证失败: %v", err)
		}

		if !valid {
			log.Fatalf("密码错误")
		}
	}

	// Generate new token pair
	accessToken, refreshToken, err := jwtService.GenerateTokenPair(user)
	if err != nil {
		log.Fatalf("生成令牌失败: %v", err)
	}

	// Output
	now := time.Now()
	out := output{
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    cfg.JWT.AccessTokenTTL.String(),
		RefreshTTL:   cfg.JWT.RefreshTokenTTL.String(),
		RenewedAt:    now.Format(time.RFC3339),
	}
	if user.Email != nil {
		out.Email = *user.Email
	}
	if user.PhoneNumber != nil {
		out.PhoneNumber = *user.PhoneNumber
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Printf("%+v\n", out)
		}
	} else {
		fmt.Printf("user_id: %s\n", out.UserID)
		fmt.Printf("access_token: %s\n", out.AccessToken)
		fmt.Printf("refresh_token: %s\n", out.RefreshToken)
		fmt.Printf("renewed_at: %s\n", out.RenewedAt)
	}

	sugar.Info("Token renewed successfully",
		"user_id", user.ID,
		"identifier", identifier,
		"renewed_at", now)
}
