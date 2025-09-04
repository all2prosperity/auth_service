# Auth Console Backend

Auth Console Backend是一个模块化的管理后台系统，为Auth Service提供管理员控制台功能。

## 功能特性

### 用户管理
- **用户检索**: 支持分页、搜索和过滤的用户列表
- **用户锁定/解锁**: 管理员可以锁定或解锁用户账户
- **角色管理**: 更新用户角色权限
- **令牌撤销**: 撤销用户的所有活跃令牌

### 审计日志
- **操作记录**: 记录所有管理员操作
- **日志查询**: 支持按用户、操作类型、时间范围查询
- **审计追踪**: 完整的操作追踪链

### 统计分析
- **验证码统计**: 查看验证码发送和验证统计
- **用户统计**: 用户注册、活跃度等统计信息

### 系统设置
- **JWT配置**: 管理JWT令牌设置
- **SMTP设置**: 配置邮件发送参数
- **SMS设置**: 配置短信发送参数
- **安全设置**: 管理登录限制、锁定策略等

## 架构设计

### 模块化架构
Console采用模块化设计，支持两种运行模式：

1. **集成模式**: 作为auth-server的内置模块运行
2. **独立模式**: 作为独立服务运行

### 核心组件

```
internal/console/
├── audit/          # 审计日志模块
├── rbac/           # 权限控制模块
├── metrics/        # 监控指标模块
├── store/          # 数据访问层
├── service/        # 业务逻辑层
├── handler/        # HTTP处理层
└── console.go      # 模块引导程序
```

#### 1. 审计模块 (audit)
- 记录所有管理员操作
- 支持结构化日志查询
- 自动清理过期日志

#### 2. 权限控制 (rbac)
- 基于角色的访问控制
- 支持多种管理员角色：
  - `admin`: 完全管理权限
  - `secops`: 安全运维权限  
  - `support`: 客服支持权限

#### 3. 监控指标 (metrics)
- Prometheus兼容的指标
- 操作计数和延迟统计
- 错误率监控

#### 4. 数据访问层 (store)
- 抽象的存储接口
- 支持直接数据库访问（集成模式）
- 支持RPC调用（独立模式）

#### 5. 业务逻辑层 (service)
- 权限验证
- 限流控制
- 业务规则实现

#### 6. HTTP处理层 (handler)
- REST API接口
- JWT令牌验证
- 请求参数解析

## 部署方式

### 集成模式
在auth-server中直接集成console模块：

```go
// main.go
import "github.com/all2prosperity/auth_service/internal/console"

// 初始化console模块
consoleConfig := console.Config{
    JWTSecret: cfg.JWT.AccessSecret,
    Enabled:   true,
}

consoleModule, err := console.NewConsole(db.DB, consoleConfig)
if err != nil {
    log.Fatalf("Failed to initialize console: %v", err)
}

// 注册路由
consoleModule.RegisterRoutes(router)
```

### 独立模式
作为独立服务运行：

```bash
# 编译独立服务
go build -o console-server ./cmd/console/

# 运行
./console-server -port 8081
```

## API接口

### 用户管理

#### 获取用户列表
```http
GET /admin/users?page=1&page_size=20&search=john&status=active&role=user
Authorization: Bearer <admin_jwt_token>
```

#### 获取单个用户
```http
GET /admin/users/{user_id}
Authorization: Bearer <admin_jwt_token>
```

#### 锁定用户
```http
POST /admin/users/{user_id}/lock
Authorization: Bearer <admin_jwt_token>
Content-Type: application/x-www-form-urlencoded

reason=违规操作
```

#### 解锁用户
```http
POST /admin/users/{user_id}/unlock
Authorization: Bearer <admin_jwt_token>
Content-Type: application/x-www-form-urlencoded

reason=申诉通过
```

#### 更新用户角色
```http
PUT /admin/users/{user_id}/role
Authorization: Bearer <admin_jwt_token>
Content-Type: application/x-www-form-urlencoded

role=support
```

#### 撤销用户令牌
```http
POST /admin/users/{user_id}/revoke-tokens
Authorization: Bearer <admin_jwt_token>
Content-Type: application/x-www-form-urlencoded

reason=安全原因
```

### 审计日志

#### 获取审计日志
```http
GET /admin/audit-logs?page=1&page_size=50&user_id={user_id}&action=user_locked&start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T23:59:59Z
Authorization: Bearer <admin_jwt_token>
```

### 统计信息

#### 获取验证码统计
```http
GET /admin/stats/codes?start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T23:59:59Z&group_by=day
Authorization: Bearer <admin_jwt_token>
```

### 系统设置

#### 获取系统设置
```http
GET /admin/settings
Authorization: Bearer <admin_jwt_token>
```

#### 更新系统设置
```http
PUT /admin/settings
Authorization: Bearer <admin_jwt_token>
Content-Type: application/json

{
  "jwt": {
    "access_token_ttl_minutes": 60,
    "refresh_token_ttl_days": 30
  },
  "security": {
    "max_login_attempts": 5,
    "lockout_duration_minutes": 30
  }
}
```

## 权限控制

### 角色定义

#### Admin (admin)
- 所有权限
- 可以管理所有用户（除其他admin）
- 可以修改系统设置
- 可以分配secops和support角色

#### Security Operations (secops)
- 用户管理权限（查看、锁定、解锁）
- 令牌撤销权限
- 审计日志查看权限
- 统计信息查看权限
- 系统设置查看权限（只读）
- 可以分配support角色

#### Support (support)
- 用户查看权限（只读）
- 基础统计信息查看权限

### 权限验证
所有API调用都需要有效的JWT令牌，令牌中必须包含相应的管理员角色。

## 监控指标

Console模块提供以下Prometheus指标：

- `console_requests_total`: API请求总数
- `console_request_duration_seconds`: 请求延迟
- `console_user_lock_operations_total`: 用户锁定操作数
- `console_user_unlock_operations_total`: 用户解锁操作数
- `console_role_updates_total`: 角色更新操作数
- `console_token_revocations_total`: 令牌撤销操作数
- `console_audit_logs_created_total`: 审计日志创建数
- `console_errors_total`: 错误总数

## 配置说明

### 环境变量
- `CONSOLE_ENABLED`: 是否启用console模块（默认true）
- `JWT_ACCESS_SECRET`: JWT访问令牌密钥

### 数据库表
Console模块需要以下数据库表：
- `audit_logs`: 审计日志表（自动创建）
- `users`: 用户表（共享）
- `jwt_blacklist`: JWT黑名单表（共享）

## 安全考虑

1. **令牌验证**: 所有API都需要有效的管理员JWT令牌
2. **权限分离**: 基于角色的细粒度权限控制
3. **审计追踪**: 所有操作都会记录审计日志
4. **限流控制**: 对敏感操作进行限流
5. **IP记录**: 记录所有操作的来源IP

## 扩展开发

### 添加新的权限
在`rbac/rbac.go`中添加新的权限常量：

```go
const (
    PermissionNewFeature Permission = "new_feature:action"
)
```

### 添加新的API接口
1. 在service层添加业务逻辑
2. 在handler层添加HTTP处理
3. 在console.go中注册路由

### 添加新的监控指标
在`metrics/metrics.go`中添加新的指标定义。

## 故障排除

### 常见问题

1. **JWT令牌无效**
   - 检查令牌是否过期
   - 验证JWT密钥配置
   - 确认用户有管理员角色

2. **权限被拒绝**
   - 检查用户角色权限
   - 验证目标用户角色层级

3. **数据库连接错误**
   - 检查数据库配置
   - 验证网络连接
   - 确认数据库表已创建

### 日志查看
Console模块使用结构化日志，关键信息会包含：
- 操作类型
- 用户ID
- 目标资源
- 执行结果

```bash
# 查看console相关日志
grep "CONSOLE" /var/log/auth-service.log
``` 