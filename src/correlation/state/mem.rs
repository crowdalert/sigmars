use super::Key;
use super::{Backend, BackendError, CorrelationRule, RuleState};
use async_trait::async_trait;
use futures_util::StreamExt;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    RwLock,
    mpsc::{self, Receiver, Sender}
};

use tokio_util::time::delay_queue::DelayQueue;

type BackendMap = Arc<RwLock<HashMap<String, HashMap<String, HashMap<Option<String>, u64>>>>>;

pub struct MemBackendImpl {
    map: BackendMap,
    tx: Sender<(String, Key, Duration)>,
    task: tokio::task::JoinHandle<()>
}

impl MemBackendImpl {
    async fn new() -> Self {
        let map = BackendMap::default();
        let (tx, rx) = mpsc::channel::<(String, Key, Duration)>(16);
        let task = Self::start(rx, &map).await;

        MemBackendImpl {
            map,
            tx,
            task
        }
    }

    pub async fn count(&self, rule_id: &String, key: &Key) -> u64 {
        let (group_by, value) = key.into();

        self.map.read().await
            .get(rule_id)
            .map(|m| {
                m.get(&group_by)
                    .map(|v| v.get(&value).unwrap_or_else(|| &0))
                    .copied()
                    .unwrap_or(0)
            })
            .unwrap_or_else(|| 0) as u64
    }

    pub async fn incr(&self, rule_id: &String, timeout: Duration, key: &Key) -> u64 {
        let (group_by, value) = key.into();
        let mut map = self.map.write().await;
        let grouping = map
            .entry(rule_id.to_string())
            .or_insert(HashMap::new())
            .entry(group_by)
            .or_insert(HashMap::new());
        let count = grouping
            .entry(value)
            .or_insert(0);

        *count += 1;

        self.tx.send((rule_id.clone(), key.clone(), timeout)).await.unwrap();

        match key {
            Key::EventCount(_) => *count as u64,
            Key::ValueCount(_, _) => grouping.len() as u64,
        }
    }

    async fn start(mut rx: Receiver<(String, Key, Duration)>, map: &BackendMap) -> tokio::task::JoinHandle<()> {
        let map = map.clone();
        tokio::spawn(async move {
            let mut queue  = DelayQueue::<(String, Key)>::new();
            loop {
                tokio::select! {
                    Some((rule_id, key, timeout)) = rx.recv() => {
                        queue.insert((rule_id, key), timeout);
                    },
                    Some(expired) = queue.next() => {
                        let (rule_id, key) = expired.into_inner();
                        let mut map = map.write().await;

                        map.entry(rule_id)
                        .and_modify(|r| {
                            let (group_by, value) = (&key).into();
                            if let Some(e) = r.get_mut(&group_by) {
                                match e.get_mut(&value) {
                                    Some(c) => {
                                        *c -= 1;
                                        if *c <= 0 {
                                            e.remove(&value);
                                            if e.len() == 0 {
                                                r.remove(&group_by);
                                            }
                                        }
                                    },
                                    None => {
                                        r.remove(&group_by);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        })
    }
}

pub type MemBackendType = Arc<MemBackendImpl>;
pub struct MemBackend(MemBackendType);

impl MemBackend {
    pub async fn new() -> Self {
        MemBackend(Arc::new(MemBackendImpl::new().await))
    }
}

pub struct MemState {
    rule_id: String,
    timespan: Duration,
    backend: MemBackendType,
}

impl MemState {
    pub async fn new(rule_id: &String, timespan: &Duration, backend: Arc<MemBackendImpl>) -> Result<Self, BackendError> {
        Ok(MemState {
            rule_id: rule_id.clone(),
            timespan: timespan.clone(),
            backend,
        })
    }
}

#[async_trait]
impl RuleState for MemState {
    async fn incr(&self, key: &Key) -> u64 {
        self.backend.incr(&self.rule_id, self.timespan, key).await
    }

    async fn count(&self, key: &Key) -> u64 {
        self.backend.count(&self.rule_id, key).await
    }
}

#[async_trait]
impl Backend for MemBackend {
    async fn register(
        &mut self,
        rule: &mut CorrelationRule,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let state = MemState::new(&rule.inner.id, &rule.inner.timespan, self.0.clone()).await?;

        rule.inner
            .state
            .set(Box::new(state))
            .map_err(|_| {
                BackendError::StateError(format!("{}: state already initialized", rule.inner.id))
            })?;
        Ok(())
    }
}

impl Drop for MemBackendImpl {
    fn drop(&mut self) {
        self.task.abort();
    }
}
