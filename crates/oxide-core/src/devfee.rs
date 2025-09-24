// OxideMiner/crates/oxide-core/src/devfee.rs

/// 1% developer fee = 100 basis points
pub const DEV_FEE_BASIS_POINTS: u32 = 100;

/// hard coded developer donation address
pub const DEV_WALLET_ADDRESS: &str = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS";

#[derive(Debug, Clone)]
pub struct DevFeeScheduler {
    jobs_since_last: u64,
    jobs_per_donation: u64,
}

impl DevFeeScheduler {
    pub fn new() -> Self {
        let denominator = DEV_FEE_BASIS_POINTS as u64;
        let jobs_per_donation = if denominator == 0 {
            u64::MAX
        } else {
            ((10_000u64 + denominator - 1) / denominator).max(1)
        };
        Self {
            jobs_since_last: 0,
            jobs_per_donation,
        }
    }

    /// Record a newly received job. Returns `true` when the devfee donation
    /// threshold has been reached and the next job should mine for the
    /// developer wallet.
    ///
    /// `is_devfee_job` jobs are ignored for the purpose of the counter so that
    /// we donate roughly 1% of *user* work.
    pub fn record_job(&mut self, is_devfee_job: bool) -> bool {
        if is_devfee_job {
            return self.jobs_since_last >= self.jobs_per_donation;
        }

        self.jobs_since_last = self.jobs_since_last.saturating_add(1);
        self.jobs_since_last >= self.jobs_per_donation
    }

    /// Call after successfully switching to the devfee pool to reset the
    /// donation counter while preserving any overflow from the previous window.
    pub fn mark_donation_started(&mut self) {
        if self.jobs_since_last >= self.jobs_per_donation {
            self.jobs_since_last -= self.jobs_per_donation;
        } else {
            self.jobs_since_last = 0;
        }
    }

    pub fn jobs_since_last(&self) -> u64 {
        self.jobs_since_last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donate_every_hundred() {
        let mut sched = DevFeeScheduler::new();
        let interval = ((10_000 + DEV_FEE_BASIS_POINTS - 1) / DEV_FEE_BASIS_POINTS) as usize;
        let interval = interval.max(1);
        for i in 1..=200 {
            let donate = sched.record_job(false);
            if i % interval == 0 {
                assert!(donate, "expected donation on job {}", i);
                sched.mark_donation_started();
            } else {
                assert!(!donate, "unexpected donation on job {}", i);
            }
        }
    }

    #[test]
    fn dev_jobs_do_not_advance_counter() {
        let mut sched = DevFeeScheduler::new();
        // Feed a mix of devfee and user jobs; only user jobs should count
        for _ in 0..50 {
            assert!(!sched.record_job(true));
        }
        for i in 1..=100 {
            let donate = sched.record_job(false);
            if i == 100 {
                assert!(donate);
            } else {
                assert!(!donate);
            }
            if donate {
                sched.mark_donation_started();
            }
        }
        // Subsequent dev jobs should still be ignored
        assert!(!sched.record_job(true));
    }
}
