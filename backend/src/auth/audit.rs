//! Structured audit logging into the append-only `audit_logs` table.
//! Audit failures are logged but never fail the request that triggered them.
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::extractor::RequestMeta;

pub struct AuditEvent<'a> {
    pub actor_id: Option<Uuid>,
    pub actor_label: Option<&'a str>,
    pub action: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<String>,
    /// "success" | "failure" | "denied"
    pub outcome: &'a str,
    pub detail: Value,
}

impl<'a> AuditEvent<'a> {
    pub fn new(action: &'a str, outcome: &'a str) -> Self {
        Self {
            actor_id: None,
            actor_label: None,
            action,
            resource_type: None,
            resource_id: None,
            outcome,
            detail: Value::Object(Default::default()),
        }
    }
    pub fn actor(mut self, id: Uuid, label: &'a str) -> Self {
        self.actor_id = Some(id);
        self.actor_label = Some(label);
        self
    }
    pub fn label(mut self, label: &'a str) -> Self {
        self.actor_label = Some(label);
        self
    }
    pub fn resource(mut self, kind: &'a str, id: impl ToString) -> Self {
        self.resource_type = Some(kind);
        self.resource_id = Some(id.to_string());
        self
    }
    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

pub async fn record(pool: &PgPool, meta: &RequestMeta, e: AuditEvent<'_>) {
    let res = sqlx::query(
        "INSERT INTO audit_logs \
         (actor_id, actor_label, action, resource_type, resource_id, outcome, ip_address, request_id, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::text::inet, $8, $9)",
    )
    .bind(e.actor_id)
    .bind(e.actor_label)
    .bind(e.action)
    .bind(e.resource_type)
    .bind(e.resource_id)
    .bind(e.outcome)
    .bind(meta.ip.as_deref())
    .bind(meta.request_id.as_deref())
    .bind(e.detail)
    .execute(pool)
    .await;
    if let Err(err) = res {
        tracing::error!(error = %err, action = e.action, "failed to write audit log");
    }
}
