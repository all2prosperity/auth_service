package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"
	"github.com/all2prosperity/auth_service/services"

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
}

func main() {
	// Flags
	email := flag.String("email", "", "用户邮箱，可选，与 --phone 二选一")
	phone := flag.String("phone", "", "用户手机号，可选，与 --email 二选一")
	password := flag.String("password", "", "用户密码，可选，不填则创建无密码用户")
	rolesFlag := flag.String("roles", "user", "用户角色，逗号分隔，默认: user")
	configFile := flag.String("config", "", "可选，自定义配置文件路径（覆盖内置查找顺序）")
	jsonOut := flag.Bool("json", true, "是否以 JSON 输出，默认 true")
	flag.Parse()

	if *email == "" && *phone == "" {
		log.Fatal("必须提供 --email 或 --phone 其中之一")
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

	// Pre-check existing user
	if *email != "" {
		if _, err := userDAO.GetUserByEmail(*email); err == nil {
			log.Fatalf("用户已存在(email=%s)", *email)
		}
	}
	if *phone != "" {
		if _, err := userDAO.GetUserByPhoneNumber(*phone); err == nil {
			log.Fatalf("用户已存在(phone=%s)", *phone)
		}
	}

	// Build user model
	var (
		emailPtr *string
		phonePtr *string
	)
	if *email != "" {
		emailPtr = email
	}
	if *phone != "" {
		phonePtr = phone
	}

	// Parse roles
	roles := make([]string, 0)
	for _, r := range strings.Split(*rolesFlag, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			roles = append(roles, r)
		}
	}
	if len(roles) == 0 {
		roles = []string{"user"}
	}

	// Optional password
	var passwordHash *string
	if *password != "" {
		if err := passwordService.IsStrongPassword(*password); err != nil {
			log.Fatalf("密码不符合强度要求: %v", err)
		}
		h, err := passwordService.HashPassword(*password)
		if err != nil {
			log.Fatalf("密码哈希失败: %v", err)
		}
		passwordHash = &h
	}

	// Create user
	user := &models.User{
		Email:        emailPtr,
		PhoneNumber:  phonePtr,
		PasswordHash: passwordHash,
		Roles:        roles,
	}
	// 新建即视为已确认，可按需要调整
	now := time.Now()
	user.ConfirmedAt = &now

	if err := userDAO.CreateUser(user); err != nil {
		log.Fatalf("创建用户失败: %v", err)
	}

	// Generate token pair according to config TTL
	accessToken, refreshToken, err := jwtService.GenerateTokenPair(user)
	if err != nil {
		log.Fatalf("生成令牌失败: %v", err)
	}

	// Output
	out := output{
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    cfg.JWT.AccessTokenTTL.String(),
		RefreshTTL:   cfg.JWT.RefreshTokenTTL.String(),
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
		fmt.Printf("user_id: %s\naccess_token: %s\nrefresh_token: %s\n", out.UserID, out.AccessToken, out.RefreshToken)
	}
}
