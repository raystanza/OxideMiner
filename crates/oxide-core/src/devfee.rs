// OxideMiner/crates/oxide-core/src/devfee.rs

/// 1% developer fee = 100 basis points
pub const DEV_FEE_BASIS_POINTS: u32 = 100;

/// hard coded developer donation address
pub const DEV_WALLET_ADDRESS: &str = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS";

#[derive(Debug, Clone)]
pub struct DevFeeScheduler {
    /// Total jobs observed since startup (user + dev).
    observed_jobs: u64,
    /// Jobs counted toward the next donation window.
    counter: u32,
    /// When true we still owe a donation share (e.g. after a failed attempt).
    pending: bool,
}

impl DevFeeScheduler {
    pub fn new() -> Self {
        Self {
            observed_jobs: 0,
            counter: 0,
            pending: false,
        }
    }

    /// Record that a new stratum job has been received. Returns `true` when
    /// the caller should mine a developer donation share.
    pub fn should_donate(&mut self) -> bool {
        self.observed_jobs = self.observed_jobs.saturating_add(1);

        if self.pending {
            return true;
        }

        self.counter += 1;
        if self.counter >= DEV_FEE_BASIS_POINTS {
            self.pending = true;
            true
        } else {
            false
        }
    }

    /// Mark that we have successfully switched to the dev wallet so the
    /// scheduler can start counting the next window.
    pub fn mark_started(&mut self) {
        if self.pending {
            self.pending = false;
            self.counter = 0;
        }
    }

    /// Total jobs observed since the miner started.
    pub fn observed_jobs(&self) -> u64 {
        self.observed_jobs
    }

    /// Whether a donation share is still pending.
    pub fn pending(&self) -> bool {
        self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donate_every_hundred() {
        let mut sched = DevFeeScheduler::new();
        for i in 1..=200 {
            let donate = sched.should_donate();
            if i % DEV_FEE_BASIS_POINTS as usize == 0 {
                assert!(donate, "expected donation on job {}", i);
                sched.mark_started();
            } else {
                assert!(!donate, "unexpected donation on job {}", i);
            }
        }
        assert_eq!(sched.observed_jobs(), 200);
    }

    #[test]
    fn donation_stays_pending_until_started() {
        let mut sched = DevFeeScheduler::new();
        for _ in 0..(DEV_FEE_BASIS_POINTS - 1) {
            assert!(!sched.should_donate());
        }
        assert!(sched.should_donate());
        assert!(sched.pending());
        // Still pending on subsequent jobs until mark_started is called.
        assert!(sched.should_donate());
        sched.mark_started();
        assert!(!sched.pending());
        assert!(!sched.should_donate());
    }
}
