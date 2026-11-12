//! Real-time event bus. Producers (job tasks) publish; WebSocket sessions subscribe.
//! A bounded broadcast channel means a slow consumer lags (and is told to resync)
//! rather than growing memory without limit.
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    JobStarted,
    JobProgress,
    PacketDetected,
    ThreatDetected,
    CaptureStopped,
    JobCompleted,
    JobFailed,
    CleanupCompleted,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Unique per event: clients de-duplicate on this.
    pub id: Uuid,
    #[serde(rename = "type")]
    pub kind: EventKind,
    pub job_id: Uuid,
    pub ts: DateTime<Utc>,
    pub data: Value,
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Publishing never fails or blocks; with no subscribers the event is simply dropped.
    pub fn publish(&self, kind: EventKind, job_id: Uuid, data: Value) {
        let _ = self.tx.send(Event {
            id: Uuid::new_v4(),
            kind,
            job_id,
            ts: Utc::now(),
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn delivers_to_all_subscribers() {
        let bus = EventBus::new(8);
        let (mut a, mut b) = (bus.subscribe(), bus.subscribe());
        let job = Uuid::new_v4();
        bus.publish(EventKind::JobStarted, job, json!({"x": 1}));
        let (ea, eb) = (a.recv().await.unwrap(), b.recv().await.unwrap());
        assert_eq!(ea.id, eb.id);
        assert_eq!(ea.job_id, job);
        assert_eq!(serde_json::to_value(&ea).unwrap()["type"], "job_started");
    }

    #[test]
    fn publish_without_subscribers_is_harmless() {
        EventBus::new(2).publish(EventKind::JobFailed, Uuid::new_v4(), json!({}));
    }

    #[tokio::test]
    async fn slow_consumer_lags_instead_of_growing() {
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();
        for _ in 0..10 {
            bus.publish(EventKind::JobProgress, Uuid::new_v4(), json!({}));
        }
        assert!(matches!(
            rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }
}
