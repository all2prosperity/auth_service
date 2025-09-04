# Auth Service v0.3

基于 PRD 文档实现的完整身份认证服务，支持密码登录、邮箱/手机验证码登录、OAuth 社交登录等功能。

## 功能特性

### 核心功能
- ✅ 用户注册与登录（邮箱/手机号 + 密码）
- ✅ 邮箱验证码免密登录
- ✅ 手机验证码免密登录  
- ✅ JWT Token 管理（访问令牌 + 刷新令牌）
- ✅ 密码重置（邮箱/短信验证码）
- ✅ 账号锁定与解锁
- ✅ 审计日志记录
- 🚧 OAuth 社交登录（Google/GitHub/Apple/WeChat）
- 🚧 管理后台接口

### 安全特性
- Argon2id 密码哈希
- JWT 黑名单机制
- 验证码频率限制
- 登录失败锁定
- 审计日志记录

### 技术栈
- **框架**: ConnectRPC + Chi Router
- **数据库**: PostgreSQL 15
- **Token**: JWT (golang-jwt/jwt)
- **密码哈希**: Argon2id
- **邮件**: SMTP
- **短信**: Twilio（可扩展）
- **可观测性**: Prometheus metrics

## 快速开始

### 1. 环境要求

- Go 1.23+
- PostgreSQL 15+
- SMTP 邮件服务（可选，用于邮箱验证码）
- Twilio 账号（可选，用于短信验证码）

### 2. 安装依赖

```bash
cd auth_service/srv
go mod download
```

### 3. 数据库设置

创建 PostgreSQL 数据库：

```sql
CREATE DATABASE auth_service;
CREATE USER auth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
```

### 4. 环境变量配置

创建 `.env` 文件（参考 `.env.example`）：

```bash
# 基础配置
PORT=8080
DB_HOST=localhost
DB_PORT=5432
DB_USER=auth_user
DB_PASSWORD=your_password
DB_NAME=auth_service
DB_SSL_MODE=disable

# JWT 密钥（生产环境请使用强密钥）
JWT_ACCESS_SECRET=your-super-secret-access-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# SMTP 配置（可选）
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@example.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@example.com

# Twilio 配置（可选）
TWILIO_SID=your-twilio-sid
TWILIO_TOKEN=your-twilio-token
TWILIO_FROM=+1234567890
```

### 5. 数据库迁移

使用内置的迁移工具：

```bash
# 运行迁移（创建表结构）
go run cmd/migrate/main.go -action=up

# 回滚迁移（删除表结构，仅用于开发）
go run cmd/migrate/main.go -action=down

# 种子数据（创建管理员用户）
go run cmd/migrate/main.go -action=seed

# 检查迁移状态
go run cmd/migrate/main.go -action=status
```

### 5.1 管理工具

#### 创建用户
```bash
# 创建邮箱用户
go run cmd/create_user/main.go -email user@example.com -password "StrongPass123!" -roles "user"

# 创建手机用户  
go run cmd/create_user/main.go -phone "+86138888888888" -password "StrongPass123!" -roles "admin,user"
```

#### 刷新用户Token
```bash
# 通过邮箱刷新token（需要密码验证）
go run cmd/renew_token/main.go -email user@example.com -password "StrongPass123!"

# 通过手机号刷新token
go run cmd/renew_token/main.go -phone "+86138888888888" -password "StrongPass123!"

# 管理员模式：跳过密码验证（仅用于管理目的）
go run cmd/renew_token/main.go -email user@example.com -skip-auth
```

### 6. 启动服务

```bash
go run main.go
```

服务将在 `http://localhost:8080` 启动，并自动运行数据库迁移。

## API 接口

### 健康检查
```bash
curl http://localhost:8080/health
```

### 用户注册（邮箱）
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/Register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "StrongPass123!"
  }'
```

### 用户注册（手机号）
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/Register \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+86138888888888",
    "password": "StrongPass123!"
  }'
```

### 密码登录
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/Login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "StrongPass123!"
  }'
```

### 发起邮箱验证码登录
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/StartCodeLogin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### 完成邮箱验证码登录
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/CompleteCodeLogin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "code": "123456"
  }'
```

### 刷新 Token
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/RefreshToken \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token"
  }'
```

### 获取当前用户信息
```bash
curl -X POST http://localhost:8080/auth.v1.AuthService/GetMe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_access_token" \
  -d '{}'
```

## 项目结构

```
auth_service/srv/
├── main.go              # 服务入口
├── config/              # 配置管理
│   └── config.go
├── database/            # 数据库连接与初始化（GORM）
│   └── database.go
├── models/              # GORM 数据模型
│   └── models.go
├── migrations/          # 数据库迁移管理
│   └── migrations.go
├── dao/                 # 数据访问层（GORM 操作）
│   └── user_dao.go
├── cmd/                 # 命令行工具
│   └── migrate/         # 迁移工具
│       └── main.go
├── services/            # 业务服务层
│   ├── password_service.go
│   ├── jwt_service.go
│   └── code_service.go
├── handlers/            # HTTP 处理器
│   └── auth_handler.go
└── generated/           # 自动生成的 Proto 代码
    └── auth/v1/
```

## 数据库表结构

### users - 用户表
- `id` (UUID): 用户唯一标识
- `email` (TEXT): 邮箱地址（可选）
- `phone_number` (TEXT): 手机号码（可选）
- `password_hash` (TEXT): 密码哈希
- `roles` (TEXT[]): 用户角色数组
- `confirmed_at` (TIMESTAMPTZ): 确认时间
- `locked_until` (TIMESTAMPTZ): 锁定截止时间
- `created_at`, `updated_at`: 时间戳

### code_login_tokens - 验证码表
- `id` (UUID): 记录唯一标识
- `identifier` (TEXT): 邮箱或手机号
- `channel` (ENUM): 发送渠道（email/sms）
- `code` (TEXT): 验证码
- `expires_at` (TIMESTAMPTZ): 过期时间
- `used` (BOOLEAN): 是否已使用

### jwt_blacklist - JWT 黑名单
- `id` (UUID): 记录唯一标识
- `token_id` (TEXT): JWT ID
- `user_id` (UUID): 用户ID
- `expires_at` (TIMESTAMPTZ): Token 过期时间

### audit_logs - 审计日志
- `id` (UUID): 记录唯一标识
- `user_id` (UUID): 用户ID
- `action` (ENUM): 操作类型
- `ip` (INET): IP 地址
- `user_agent` (TEXT): 用户代理
- `extra` (JSONB): 额外信息

## 监控与运维

### 健康检查
```bash
curl http://localhost:8080/health
```

### Prometheus 指标
```bash
curl http://localhost:8080/metrics
```

### 日志查看
服务日志会输出到标准输出，包含：
- 请求日志
- 业务操作日志
- 错误日志
- 审计日志

## 开发说明

### 添加新的验证码渠道
1. 在 `models/models.go` 中扩展 `CodeChannel` 枚举
2. 在 `services/code_service.go` 中实现发送逻辑
3. 更新数据库表结构

### 添加新的 OAuth 提供商
1. 在 `config/config.go` 中添加配置
2. 创建对应的处理器
3. 实现 OAuth 流程

### 扩展审计功能
1. 在 `models/models.go` 中添加新的 `AuditAction`
2. 在相应的业务逻辑中调用 `logAuditEvent`

## 安全建议

### 生产环境配置
1. 使用强随机密钥作为 JWT 密钥
2. 启用 HTTPS
3. 配置合适的 CORS 策略
4. 设置数据库连接加密
5. 定期轮换密钥

### 监控告警
1. 监控登录失败率
2. 监控验证码发送量
3. 监控异常IP登录
4. 设置审计日志告警

## 常见问题

### Q: 验证码收不到？
A: 检查 SMTP/SMS 配置，查看服务日志中的错误信息。开发环境下会跳过实际发送。

### Q: JWT Token 无效？
A: 检查 JWT 密钥配置，确认 Token 未过期且未被加入黑名单。

### Q: 数据库连接失败？
A: 检查数据库配置，确认数据库服务运行正常，网络连通性正常。

### Q: 密码强度要求？
A: 密码需包含大小写字母、数字、特殊字符，长度至少8位。

## GORM 特性

### 模型定义
项目使用 GORM v2 进行数据库操作，具有以下特性：

- **自动迁移**: 启动时自动创建和更新表结构
- **关系映射**: 支持一对多、多对多关系
- **软删除**: 用户删除使用软删除（保留数据）
- **钩子函数**: BeforeCreate、AfterUpdate 等生命周期钩子
- **事务支持**: 自动事务管理和手动事务控制

### 模型特点
```go
// 基础模型，包含 ID、创建时间、更新时间、删除时间
type BaseModel struct {
    ID        uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    CreatedAt time.Time  `gorm:"autoCreateTime"`
    UpdatedAt time.Time  `gorm:"autoUpdateTime"`
    DeletedAt *time.Time `gorm:"index"`
}

// 用户模型示例
type User struct {
    BaseModel
    Email        *string     `gorm:"type:text;uniqueIndex"`
    PhoneNumber  *string     `gorm:"type:text;uniqueIndex"`
    Roles        StringArray `gorm:"type:text[];default:'{user}'"`
    // 关系映射
    SocialAccounts []SocialAccount `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}
```

### 迁移管理
- **自动迁移**: 服务启动时自动执行
- **手动迁移**: 使用 `cmd/migrate` 工具
- **版本控制**: 通过 Git 管理迁移历史
- **回滚支持**: 开发环境支持迁移回滚

### GORM 优势
1. **类型安全**: 编译时检查，减少运行时错误
2. **代码简洁**: 相比原生 SQL，代码量减少 60%+
3. **自动化**: 自动处理表结构变更和索引创建
4. **关系管理**: 简化复杂关系查询
5. **性能优化**: 内置查询优化和连接池管理

## 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

MIT License 