/// 1% developer fee = 100 basis points
pub const DEV_FEE_BASIS_POINTS: u32 = 100;

/// hard coded developer donation address
pub const DEV_WALLET_ADDRESS: &str = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS";

#[derive(Debug, Clone)]
pub struct DevFeeScheduler {
    counter: u64,
}

impl DevFeeScheduler {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Increment job counter; return true if this job should be mined to the dev address.
    pub fn should_donate(&mut self) -> bool {
        self.counter += 1;
        // 1 of every 100 jobs (simple, deterministic)
        (self.counter % 100) == 0
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
            if i % DEV_FEE_BASIS_POINTS as usize == 0 {
                assert!(donate, "expected donation on job {}", i);
            } else {
                assert!(!donate, "unexpected donation on job {}", i);
            }
        }
    }
}
