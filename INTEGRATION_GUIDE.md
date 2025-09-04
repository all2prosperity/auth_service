# Auth Service 快速集成指南

## 概述

Auth Service 是一个完整的身份认证服务，支持多种认证方式和管理功能。本指南将帮助您快速集成该服务到您的项目中。

## 🚀 快速开始

### 1. 环境准备

**必需组件：**
- Go 1.23+
- PostgreSQL 15+

**可选组件：**
- SMTP 服务器（用于邮件验证）
- Twilio 账号（用于短信验证）
- Redis（用于缓存，可选）

### 2. 安装依赖

```bash
# 克隆或添加依赖
go mod init your-project
go get github.com/all2prosperity/auth_service
```

### 3. 数据库设置

```sql
-- 创建数据库和用户
CREATE DATABASE auth_service;
CREATE USER auth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
```

## 📋 集成方式

### 方式一：作为模块集成（推荐）

#### 步骤 1: 初始化 Auth 模块

```go
package main

import (
    "log"
    
    auth "github.com/all2prosperity/auth_service/auth"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

func main() {
    // 1. 连接数据库
    dsn := "host=localhost port=5432 user=auth_user password=your_password dbname=auth_service sslmode=disable"
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal("数据库连接失败:", err)
    }

    // 2. 初始化 Auth 模块
    authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
        DB:             db,          // 使用您的数据库连接
        ConsoleEnabled: true,        // 启用管理控制台
        Logger:         log.Default(), // 使用您的日志器
    })
    if err != nil {
        log.Fatal("Auth 模块初始化失败:", err)
    }
    defer authModule.Close()

    // 3. 创建 HTTP 服务器
    router := setupRouter(authModule)
    
    // 4. 启动服务器
    log.Println("服务器启动在端口 8080")
    log.Fatal(http.ListenAndServe(":8080", router))
}
```

#### 步骤 2: 设置路由

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/go-chi/cors"
)

func setupRouter(authModule *auth.AuthModule) http.Handler {
    router := chi.NewRouter()

    // 基础中间件
    router.Use(middleware.Logger)
    router.Use(middleware.Recoverer)
    router.Use(middleware.RequestID)
    router.Use(middleware.Timeout(60 * time.Second))

    // CORS 配置
    router.Use(cors.Handler(cors.Options{
        AllowedOrigins:   []string{"*"}, // 生产环境请配置具体域名
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
        ExposedHeaders:   []string{"Link"},
        AllowCredentials: true,
        MaxAge:           300,
    }))

    // ConnectRPC CORS 支持
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

    // 健康检查
    router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
        if err := authModule.Health(); err != nil {
            http.Error(w, fmt.Sprintf("服务不健康: %v", err), http.StatusServiceUnavailable)
            return
        }
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    // 注册认证服务路由
    authModule.RegisterRoutes(router)

    // 注册管理控制台路由（可选）
    consoleMux := http.NewServeMux()
    authModule.RegisterConsoleRoutes(consoleMux)
    router.Mount("/admin", consoleMux)

    // 您的业务路由
    router.Route("/api/v1", func(r chi.Router) {
        r.Get("/profile", getProfile)
        // ... 其他业务路由
    })

    return router
}
```

### 方式二：独立服务部署

#### 步骤 1: 配置文件

创建 `config.yaml`:

```yaml
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"

database:
  host: "localhost"
  port: 5432
  user: "auth_user"
  password: "your_password"
  db_name: "auth_service"
  ssl_mode: "disable"
  max_open_conns: 25
  max_idle_conns: 25
  conn_max_lifetime: "5m"

jwt:
  access_secret: "your_access_secret_key_at_least_32_characters"
  refresh_secret: "your_refresh_secret_key_at_least_32_characters"
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"
  issuer: "auth-service"

logging:
  level: "info"
  format: "json"
  output: "stdout"

features:
  enable_console: true
  enable_metrics: true
  enable_cors: true
  enable_health_check: true
```

#### 步骤 2: 启动服务

```bash
# 方法 1: 直接运行
go run cmd/server/main.go

# 方法 2: 构建后运行
go build -o auth_service cmd/server/main.go
./auth_service

# 方法 3: 使用 Docker（如果有 Dockerfile）
docker build -t auth_service .
docker run -p 8080:8080 auth_service
```

## 🔧 配置说明

### 环境变量配置

```bash
# 数据库配置
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_USER=auth_user
export DATABASE_PASSWORD=your_password
export DATABASE_DB_NAME=auth_service

# JWT 配置
export JWT_ACCESS_SECRET=your_access_secret
export JWT_REFRESH_SECRET=your_refresh_secret
export JWT_ACCESS_TOKEN_TTL=15m
export JWT_REFRESH_TOKEN_TTL=7d

# SMTP 配置（可选）
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your_email@gmail.com
export SMTP_PASSWORD=your_app_password
export SMTP_FROM_EMAIL=your_email@gmail.com
export SMTP_TLS=true

# SMS 配置（可选）
export SMS_PROVIDER=twilio
export SMS_TWILIO_SID=your_twilio_sid
export SMS_TWILIO_TOKEN=your_twilio_token
export SMS_TWILIO_FROM=+1234567890
```

### 配置优先级

配置加载顺序（后者覆盖前者）：
1. `configs/local.yaml`
2. `configs/auth.yaml`
3. `config.yaml`
4. 环境变量

## 📡 API 使用

### 用户注册

```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/RegisterWithPassword \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### 用户登录

```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/LoginWithPassword \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### 邮箱验证码登录

```bash
# 1. 发送验证码
curl -X POST http://localhost:8080/auth.v1.AuthService/StartCodeLogin \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "user@example.com",
    "channel": "email"
  }'

# 2. 验证登录
curl -X POST http://localhost:8080/auth.v1.AuthService/CompleteCodeLogin \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "user@example.com",
    "channel": "email",
    "code": "123456"
  }'
```

### Token 刷新

```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/RefreshToken \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token"
  }'
```

## 🎯 业务集成示例

### JWT Token 验证中间件

```go
func JWTAuthMiddleware(authModule *auth.AuthModule) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            if token == "" {
                http.Error(w, "缺少 Authorization 头", http.StatusUnauthorized)
                return
            }

            // 移除 "Bearer " 前缀
            if strings.HasPrefix(token, "Bearer ") {
                token = token[7:]
            }

            // 这里您需要使用 authModule 的 JWT 服务验证 token
            // 实际实现需要访问 authModule 的内部 JWT 服务
            
            next.ServeHTTP(w, r)
        })
    }
}
```

### 获取用户信息

```go
func getProfile(w http.ResponseWriter, r *http.Request) {
    // 从 JWT token 中提取用户 ID
    userID := getUserIDFromToken(r) // 您需要实现此函数
    
    // 使用 auth 模块的数据库查询用户信息
    // 在实际应用中，您可以通过 authModule.GetDatabase() 获取数据库实例
    
    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"user_id": "%s", "email": "user@example.com"}`, userID)
}
```

## 🛠️ 管理操作

### 创建用户（CLI）

```bash
go run cmd/create_user/main.go \
  -email="admin@example.com" \
  -password="AdminPassword123!" \
  -roles="admin,user"
```

### 数据库迁移

```bash
# 应用迁移
go run cmd/migrate/main.go -action=up

# 回滚迁移
go run cmd/migrate/main.go -action=down

# 种子数据
go run cmd/migrate/main.go -action=seed
```

### 管理控制台

访问 `http://localhost:8080/admin` 进入管理控制台（需要管理员权限）。

## 📊 监控和健康检查

### 健康检查端点

```bash
# 服务健康状态
curl http://localhost:8080/health

# Prometheus 指标
curl http://localhost:8080/metrics
```

### Kubernetes 就绪性探针

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: auth-service
    image: auth-service:latest
    ports:
    - containerPort: 8080
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
```

## 🔒 安全最佳实践

### 1. JWT 密钥管理
- 使用至少 32 字符的随机密钥
- 定期轮换密钥
- 不同环境使用不同密钥

### 2. 数据库安全
- 使用专用数据库用户
- 启用 SSL/TLS 连接
- 定期备份数据库

### 3. 生产环境配置
- 设置适当的 CORS 策略
- 启用 HTTPS
- 配置速率限制
- 监控异常登录行为

## 🚨 故障排除

### 常见问题

**问题 1：数据库连接失败**
```bash
# 检查数据库连接
psql -h localhost -p 5432 -U auth_user -d auth_service
```

**问题 2：JWT 验证失败**
- 检查 JWT 密钥配置
- 确认 token 格式正确
- 验证 token 是否过期

**问题 3：邮件发送失败**
- 检查 SMTP 配置
- 验证邮箱服务器设置
- 确认防火墙设置

### 调试模式

```bash
# 启用调试日志
export LOGGING_LEVEL=debug
go run cmd/server/main.go
```

## 📚 进阶功能

### OAuth 集成（开发中）

```yaml
oauth:
  base_url: "http://localhost:8080"
  google:
    client_id: "your_google_client_id"
    client_secret: "your_google_client_secret"
    redirect_url: "http://localhost:8080/auth/google/callback"
```

### Redis 缓存

```yaml
redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
```

### 自定义配置

```go
// 高级配置示例
authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
    DB:             db,
    Redis:          redisClient,      // 自定义 Redis 客户端
    Config:         customConfig,     // 自定义配置
    LoggerManager:  loggerManager,    // 自定义日志管理器
    ConsoleEnabled: true,
})
```

## 📝 总结

通过本指南，您应该能够：

1. ✅ 快速集成 Auth Service 到您的项目
2. ✅ 配置必要的环境和依赖
3. ✅ 理解基本的 API 使用方法
4. ✅ 实施安全最佳实践
5. ✅ 解决常见问题

如需更详细的 API 文档和高级配置，请参考项目的完整文档。

---

**需要帮助？**
- 查看 [示例代码](examples/example_integration.go)
- 阅读 [API 文档](generated/auth/v1/authv1connect/)
- 检查 [配置选项](config/config.go)