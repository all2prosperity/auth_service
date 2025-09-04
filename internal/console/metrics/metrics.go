package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all console-related Prometheus metrics
type Metrics struct {
	// Request counters
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	ActiveSessions  prometheus.Gauge

	// User management metrics
	UserLockOperations   *prometheus.CounterVec
	UserUnlockOperations *prometheus.CounterVec
	RoleUpdates          *prometheus.CounterVec
	TokenRevocations     *prometheus.CounterVec

	// Audit metrics
	AuditLogsCreated  prometheus.Counter
	AuditQueriesTotal *prometheus.CounterVec

	// Settings metrics
	SettingsUpdates *prometheus.CounterVec

	// Error metrics
	ErrorsTotal *prometheus.CounterVec
}

// NewMetrics creates and registers all console metrics
func NewMetrics() *Metrics {
	return &Metrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_requests_total",
				Help: "Total number of console API requests",
			},
			[]string{"method", "endpoint", "status"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "console_request_duration_seconds",
				Help:    "Duration of console API requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),

		ActiveSessions: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "console_active_sessions",
				Help: "Number of active console sessions",
			},
		),

		UserLockOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_user_lock_operations_total",
				Help: "Total number of user lock operations",
			},
			[]string{"admin_id", "reason"},
		),

		UserUnlockOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_user_unlock_operations_total",
				Help: "Total number of user unlock operations",
			},
			[]string{"admin_id", "reason"},
		),

		RoleUpdates: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_role_updates_total",
				Help: "Total number of role update operations",
			},
			[]string{"admin_id", "old_role", "new_role"},
		),

		TokenRevocations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_token_revocations_total",
				Help: "Total number of token revocation operations",
			},
			[]string{"admin_id", "reason"},
		),

		AuditLogsCreated: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "console_audit_logs_created_total",
				Help: "Total number of audit logs created",
			},
		),

		AuditQueriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_audit_queries_total",
				Help: "Total number of audit log queries",
			},
			[]string{"admin_id"},
		),

		SettingsUpdates: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_settings_updates_total",
				Help: "Total number of settings update operations",
			},
			[]string{"admin_id", "setting_type"},
		),

		ErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "console_errors_total",
				Help: "Total number of console errors",
			},
			[]string{"operation", "error_type"},
		),
	}
}

// RecordRequest records a request metric
func (m *Metrics) RecordRequest(method, endpoint, status string) {
	m.RequestsTotal.WithLabelValues(method, endpoint, status).Inc()
}

// RecordRequestDuration records request duration
func (m *Metrics) RecordRequestDuration(method, endpoint string, duration float64) {
	m.RequestDuration.WithLabelValues(method, endpoint).Observe(duration)
}

// RecordUserLock records a user lock operation
func (m *Metrics) RecordUserLock(adminID, reason string) {
	m.UserLockOperations.WithLabelValues(adminID, reason).Inc()
}

// RecordUserUnlock records a user unlock operation
func (m *Metrics) RecordUserUnlock(adminID, reason string) {
	m.UserUnlockOperations.WithLabelValues(adminID, reason).Inc()
}

// RecordRoleUpdate records a role update operation
func (m *Metrics) RecordRoleUpdate(adminID, oldRole, newRole string) {
	m.RoleUpdates.WithLabelValues(adminID, oldRole, newRole).Inc()
}

// RecordTokenRevocation records a token revocation operation
func (m *Metrics) RecordTokenRevocation(adminID, reason string) {
	m.TokenRevocations.WithLabelValues(adminID, reason).Inc()
}

// RecordAuditLogCreated increments audit log creation counter
func (m *Metrics) RecordAuditLogCreated() {
	m.AuditLogsCreated.Inc()
}

// RecordAuditQuery records an audit log query
func (m *Metrics) RecordAuditQuery(adminID string) {
	m.AuditQueriesTotal.WithLabelValues(adminID).Inc()
}

// RecordSettingsUpdate records a settings update operation
func (m *Metrics) RecordSettingsUpdate(adminID, settingType string) {
	m.SettingsUpdates.WithLabelValues(adminID, settingType).Inc()
}

// RecordError records an error
func (m *Metrics) RecordError(operation, errorType string) {
	m.ErrorsTotal.WithLabelValues(operation, errorType).Inc()
}

// SetActiveSessions sets the number of active sessions
func (m *Metrics) SetActiveSessions(count float64) {
	m.ActiveSessions.Set(count)
}

// IncrementActiveSessions increments active sessions
func (m *Metrics) IncrementActiveSessions() {
	m.ActiveSessions.Inc()
}

// DecrementActiveSessions decrements active sessions
func (m *Metrics) DecrementActiveSessions() {
	m.ActiveSessions.Dec()
}
