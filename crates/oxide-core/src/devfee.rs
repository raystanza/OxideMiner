// OxideMiner/crates/oxide-core/src/devfee.rs

/// 1% developer fee = 100 basis points
pub const DEV_FEE_BASIS_POINTS: u32 = 100;

/// hard coded developer donation address
pub const DEV_WALLET_ADDRESS: &str = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS";

#[derive(Debug, Clone)]
pub struct DevFeeScheduler {
    counter: u64,
    interval: u64,
}

impl Default for DevFeeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl DevFeeScheduler {
    pub fn new() -> Self {
        let interval = (10_000u64 / DEV_FEE_BASIS_POINTS as u64).max(1);
        Self {
            counter: 0,
            interval,
        }
    }

    /// Increment the job counter and return `true` when this job should be devoted to the
    /// developer donation wallet. This must be called for *every* job (user + dev) to keep the
    /// cadence deterministic.
    pub fn should_donate(&mut self) -> bool {
        self.counter = self.counter.saturating_add(1);
        self.counter.is_multiple_of(self.interval)
    }

    /// Roll back the last counted job. Useful when a donation activation fails and we want to
    /// retry on the next job instead of waiting another full interval.
    pub fn revert_last_job(&mut self) {
        if self.counter > 0 {
            self.counter -= 1;
        }
    }

    /// Current number of jobs observed since startup.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Configured cadence (in jobs) between dev fee activations.
    pub fn interval(&self) -> u64 {
        self.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donate_every_hundred() {
        let mut sched = DevFeeScheduler::new();
        for i in 1..200 {
            let donate = sched.should_donate();
            if i % (sched.interval() as usize) == 0 {
                assert!(donate, "expected donation on job {}", i);
            } else {
                assert!(!donate, "unexpected donation on job {}", i);
            }
        }
    }

    #[test]
    fn revert_allows_retry() {
        let mut sched = DevFeeScheduler::new();
        for _ in 0..(sched.interval() - 1) {
            assert!(!sched.should_donate());
        }
        assert!(sched.should_donate());
        assert_eq!(sched.counter(), sched.interval());

        sched.revert_last_job();
        assert_eq!(sched.counter(), sched.interval() - 1);
        assert!(sched.should_donate());
    }
}
