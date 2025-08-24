/// 1% developer fee = 100 basis points
pub const DEV_FEE_BASIS_POINTS: u32 = 100;

#[derive(Debug, Clone)]
pub struct DevFeeScheduler {
    counter: u64,
}

impl DevFeeScheduler {
    pub fn new() -> Self { Self { counter: 0 } }

    /// Increment job counter; return true if this job should be mined to the dev address.
    pub fn should_donate(&mut self) -> bool {
        self.counter += 1;
        // 1 of every 100 jobs (simple, deterministic)
        (self.counter % 100) == 0
    }
}
