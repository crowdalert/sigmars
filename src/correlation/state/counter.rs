use futures_util::StreamExt;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use tokio_util::time::delay_queue::DelayQueue;

#[derive(Debug)]
pub struct Counter<T, K> {
    map: Arc<RwLock<HashMap<String, T>>>,
    tx: Sender<K>,
    task: JoinHandle<()>,
}

pub type EventCount = Counter<i64, String>;
pub type ValueCount = Counter<HashMap<String, i64>, (String, String)>;

#[derive(Debug)]
pub enum CorrelationState {
    EventCount(EventCount),
    ValueCount(ValueCount),
}
impl ValueCount {
    pub async fn has_entry(&self, groupkey: &String, key: &String) -> bool {
        let map = self.map.read().await;
        if let Some(groupby) = map.get(groupkey) {
            return groupby.contains_key(key);
        }
        false
    }
}
pub trait CountParameter<T, K>
where
    T: Send + Sync + 'static,
    K: Send + Sync + Clone + 'static,
{
    fn incr_entry(_: &mut HashMap<String, T>, _: &K);
    fn decr_entry(_: &mut HashMap<String, T>, _: &K);
    fn count(_: &HashMap<String, T>, _: &String) -> i64;
}

impl<T, K> Counter<T, K>
where
    T: CountParameter<T, K> + Send + Sync + 'static,
    K: Send + Sync + Clone + 'static,
{
    pub async fn new(timeout: Duration) -> Self {
        let map = Arc::new(RwLock::new(HashMap::<String, T>::new()));
        let (tx, rx) = channel::<K>(10);
        let task = tokio::spawn(Self::run_queue(rx, map.clone(), timeout));
        Self { map, task, tx }
    }

    async fn run_queue(
        mut rx: Receiver<K>,
        map: Arc<RwLock<HashMap<String, T>>>,
        timeout: Duration,
    ) {
        let mut queue: DelayQueue<K> = DelayQueue::new();
        loop {
            tokio::select! {
                Some(recv) = queue.next(), if map.read().await.len() > 0 => {
                    let key = recv.into_inner();
                    let mut map = map.write().await;
                    T::decr_entry(&mut map, &key);
                },
                recv = rx.recv() => {
                    if let Some(key) = recv {
                        queue.insert(key.clone(), timeout);
                    } else {
                        break;
                    }
                }

            }
        }
    }

    pub async fn incr(&self, key: &K) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = self.map.write().await;
        T::incr_entry(&mut map, &key);
        drop(map);
        self.tx.send(key.clone()).await?;
        Ok(())
    }

    pub async fn count(&self, key: &String) -> i64 {
        let map = self.map.read().await;
        let count = T::count(&map, key);
        count
    }
}

impl CountParameter<i64, String> for i64 {
    fn incr_entry(map: &mut HashMap<String, i64>, key: &String) {
        map.entry(key.to_string())
            .and_modify(|v| *v += 1)
            .or_insert(1);
    }
    fn decr_entry(map: &mut HashMap<String, i64>, key: &String) {
        match map.entry(key.to_string()).and_modify(|v| *v -= 1) {
            Entry::Occupied(v) => {
                if *(v.get()) <= 0 {
                    v.remove();
                }
            }
            _ => {}
        }
    }
    fn count(map: &HashMap<String, i64>, key: &String) -> i64 {
        match map.get(key) {
            Some(v) => *v,
            None => 0,
        }
    }
}

impl CountParameter<HashMap<String, i64>, (String, String)> for HashMap<String, i64> {
    fn incr_entry(map: &mut HashMap<String, HashMap<String, i64>>, selector: &(String, String)) {
        let (key, value) = selector;
        map.entry(key.to_string())
            .and_modify(|v| {
                v.entry(value.clone()).and_modify(|v| *v += 1).or_insert(1);
            })
            .or_insert_with(|| HashMap::from([(value.clone(), 1)]));
    }
    fn decr_entry(map: &mut HashMap<String, HashMap<String, i64>>, selector: &(String, String)) {
        let (key, value) = selector;
        if let Entry::Occupied(mut entry) = map.entry(key.to_string()) {
            if let Entry::Occupied(mut v) = entry.get_mut().entry(value.clone()) {
                if *v.get() <= 1 {
                    v.remove();
                } else {
                    *v.get_mut() -= 1;
                }
            }
            if entry.get().len() <= 0 {
                entry.remove();
            }
        }
    }
    fn count(map: &HashMap<String, HashMap<String, i64>>, key: &String) -> i64 {
        if let Some(v) = map.get(key) {
            return v.values().sum();
        }
        0
    }
}

impl<T, K> Drop for Counter<T, K> {
    fn drop(&mut self) {
        self.task.abort();
    }
}
