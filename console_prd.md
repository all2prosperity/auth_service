## Auth Console Backend – 模块化 PRD

**版本** v1.0 | **发布日期** 2025-06-14

> 本文定义 **Auth Console Backend**（简称 **console-svc**）的后端需求。
>
> * **集成模式**：作为 *auth-server* 内的一个可插拔模块启动，可以集成到auth service中直接提供console api。
> * **独立模式**：也可以单独作为一个进程发布。总之这个服务是要模块化。

---

### 1. 目标与非目标

| 范畴      | 说明                                                                                                       |
| ------- | -------------------------------------------------------------------------------------------------------- |
| **目标**  | 1) 暴露管理 API（用户检索（通过user_id,phone_number,email、锁号、角色编辑、审计查询、验证码统计、系统配置）<br>2) 供 Vue Console UI 调用；3) 完整记录审计日志；4) 与 auth-core 解耦，支持水平拆分 |

---

### 2. 高层架构

```txt
            ┌───── Vue Console UI (HTTPS, Connect-Web) ─────┐
            │                                               │
┌───────────▼───────────┐                      ┌────────────▼───────────┐
│   auth-server (集成)  │                      │  console-svc (独立)    │
│ ┌───────────────────┐ │  internal gRPC      │ ┌─────────────────────┐ │
│ │   auth-core API   │◄──────────────────────┤ │    console API      │ │
│ └───────────────────┘ │                     │ └─────────────────────┘ │
│ ┌───────────────────┐ │   function calls    │  REST/gRPC ► auth-core │
│ │  console module   │─▲─────────────────────┘             (Token / DB)│
│ └───────────────────┘ │                                    └──────────┘
└───────────────────────┘                   Shared DB (users, audit, …)
```

* **Integrated**：`main.go` `--enable-console` 加载 `console.InitRouter()`。
* **Standalone**：`go build -tags console_only -o console-svc cmd/console/*.go`
  → 以 `RPC_TARGET=auth-core:8080` 启动；数据仍写同一 Postgres。

---

### 3. 模块划分

| 模块            | 目录 (Go)                                    | 主要职责                                   |
| ------------- | ------------------------------------------ | -------------------------------------- |
| **api**       | `protos/console/v1/auth_admin.proto`             | 管理 Proto IDL；Connect・gRPC・OpenAPI 同源生成 |
| **handler**   | `internal/console/handler/`                | RPC / REST 适配层，参数校验、JWT 解析、RBAC Guard  |
| **service**   | `internal/console/service/`                | 业务逻辑 (用户搜索、聚合统计、配置管理)                  |
| **store**     | `internal/console/store/`                  | SQL/Cache DAO；复用 auth-core 的 `dbx`     |
| **rbac**      | `internal/console/rbac/`                   | 简易 RoleGuard；未来可接 Casbin               |
| **audit**     | `internal/console/audit/`                  | 写入 `audit_logs`                        |
| **metrics**   | `internal/console/metrics/`                | Prometheus counter / histogram         |
| **settings**  | `internal/console/settings/`               | JWT TTL、SMTP/SMS 渠道表维护                 |
| **bootstrap** | `cmd/auth/main.go` + `cmd/console/main.go` | 启动集成 / 独立模式                            |

---

---

### 4. 集成 vs 独立 切换点

| 项目      | 集成模式                               | 独立模式                                           |
| ------- | ---------------------------------- | ---------------------------------------------- |
| **启动**  | `auth-server --enable-console`     | `console-svc --rpc_target=auth-core:8080`      |
| **数据源** | 直接访问本进程 DB 连接池                     | 通过 auth-core RPC 读写（ListUsers, LockUser…）      |
| **鉴权**  | 同 auth-server 的 JWT middleware     | 自己的 JWT middleware + introspection 至 auth-core |
| **配置**  | 读取 `.env` 中 `CONSOLE_*`            | 独立 `.env`，支持 ConfigMap                         |
| **构建**  | 单镜像，多模块                            | 单独镜像（镜像体积 ≈ 30 MB）                             |
| **发布**  | Helm values:`console.enabled=true` | Helm 子 Chart 或 Argo App                        |

> **抽象点**：所有 DB 操作都走接口 `internal/console/store.Store`；整合时实现 `store.WithDB`, 拆分时实现 `store.WithRPC`.

---

### 5. 安全与审计

| 领域   | 措施                                                          |
| ---- | ----------------------------------------------------------- |
| 身份   | Console UI 登录后获取 access\_token；需 `admin` 或 `secops` 角色      |
| 授权   | `RoleGuard` 中间件检查 `ctx.roles`                               |
| 审计   | 每个 mutating RPC 调 `audit.Log(ctx, action, targetID, extra)` |
| 速率限制 | `rate.NewLimiter` IP+user 双维度，变更 ≤ 10/min                   |
| 日志   | 结构化 zap；日志等级可热切换                                            |
| 加密   | gRPC TLS；内部证书由 cert-manager                                 |

---

### 6. 性能与容量

| 指标       | 目标                             |
| -------- | ------------------------------ |
| P95 列表查询 | ≤ 150 ms / 50 行                |
| 峰值 QPS   | 200（运维场景）                      |
| 代码登录聚合   | 秒级窗口内查询 12 h 数据时 CPU < 1 vCore |
| 内存占用     | 集成 ≤ 300 MB；独立 ≤ 150 MB        |

---

### 7. 里程碑（4 周）

| 周  | 里程碑                            | 交付                      |
| -- | ------------------------------ | ----------------------- |
| W1 | Proto 冻结 / 代码骨架                | `console.proto`、集成模式可编译 |
| W2 | 用户、角色、锁号、Revoke RPC 完成         | Postman 测试 & 单测通过       |
| W3 | Audit & Code Stats、Settings 模块 | Prom 指标、RBAC Guard      |
| W4 | 独立模式启动脚手架、Helm 子 Chart、e2e 测试  | v1.0 Tag                |

---

### 10. 迁移路线图

1. **Phase 0** – *集成*：默认随 auth-server 启动，快速验证功能。
2. **Phase 1** – *独立灰度*：在 staging 以独立容器运行，后端切 RPC 路径。
3. **Phase 2** – *完全剥离*：prod 也改为独立部署；auth-server 移除 `--enable-console`。
4. **Phase 3** – *可扩展*：console-svc 进一步聚合 Casbin / 多租户策略 UI。

---

## 总结

* **模块化代码布局 + 双入口编译** → 同一份源码即可集成亦可独立。
* **专属 console.proto** 定义全部管理 RPC，前端 Vue UI 零胶水调用。
* **安全 & 审计** 覆盖每一次后台变更，可回溯、可配速率。
* 随着业务增长，可平滑迁移到独立微服务，无需重写逻辑或 DB。
