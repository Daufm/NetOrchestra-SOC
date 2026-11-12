//! Job registry: concurrency limiting, cancellation handles and crash recovery.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct JobManager {
    slots: Arc<Semaphore>,
    running: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl JobManager {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max_concurrent)),
            running: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve a concurrency slot without waiting; `None` means the server is at capacity.
    pub fn try_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }

    pub fn register(&self, job_id: Uuid) -> CancellationToken {
        let token = CancellationToken::new();
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job_id, token.clone());
        token
    }

    pub fn unregister(&self, job_id: Uuid) {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&job_id);
    }

    /// Request a graceful stop. False if the job is not running in this process.
    pub fn stop(&self, job_id: Uuid) -> bool {
        match self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&job_id)
        {
            Some(t) => {
                t.cancel();
                true
            }
            None => false,
        }
    }

    pub fn running_count(&self) -> usize {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Jobs left queued/running by a crashed or restarted process can never finish: fail them.
pub async fn recover_orphans(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE capture_jobs SET status = 'failed', finished_at = now(), \
            error_message = 'interrupted by server restart' \
         WHERE status IN ('queued', 'running', 'stopping')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE worker_sessions SET status = 'failed', ended_at = now(), error_message = 'interrupted by server restart' \
         WHERE status IN ('connecting', 'active', 'closing')",
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_bounded() {
        let m = JobManager::new(2);
        let (a, b) = (m.try_slot(), m.try_slot());
        assert!(a.is_some() && b.is_some());
        assert!(m.try_slot().is_none());
        drop(a);
        assert!(m.try_slot().is_some());
    }

    #[test]
    fn stop_cancels_registered_jobs_only() {
        let m = JobManager::new(1);
        let id = Uuid::new_v4();
        let t = m.register(id);
        assert_eq!(m.running_count(), 1);
        assert!(!m.stop(Uuid::new_v4()));
        assert!(m.stop(id));
        assert!(t.is_cancelled());
        m.unregister(id);
        assert_eq!(m.running_count(), 0);
        assert!(!m.stop(id));
    }
}
