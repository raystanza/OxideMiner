use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::broadcast, task::JoinHandle, time::sleep};
use tracing::info;

use crate::stratum::PoolJob;

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub job: PoolJob,
}

pub struct WorkerHandle {
    pub stop: Arc<AtomicBool>,
    pub task: JoinHandle<()>,
}

/// Spawns `n` workers; each subscribes to the same broadcast stream of jobs.
pub fn spawn_workers(n: usize, tx: broadcast::Sender<WorkItem>) -> Vec<WorkerHandle> {
    (0..n)
        .map(|idx| {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = Arc::clone(&stop);

            // Each worker gets its own receiver
            let mut rx = tx.subscribe();

            let task = tokio::spawn(async move {
                info!("worker {idx} started");
                while !stop_clone.load(Ordering::Relaxed) {
                    match rx.recv().await {
                        Ok(work) => {
                            let _ = work.job; // TODO: RandomX hashing here
                            sleep(Duration::from_millis(50)).await;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            info!("worker {idx} lagged; skipped {skipped} jobs");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                info!("worker {idx} exiting");
            });

            WorkerHandle { stop, task }
        })
        .collect()
}
