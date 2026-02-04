use std::{
    ops::{Add, AddAssign},
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(u64);

impl UtcTimestamp {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
}

impl From<u64> for UtcTimestamp {
    fn from(secs_since_unix_epoch: u64) -> Self {
        Self(secs_since_unix_epoch)
    }
}

impl From<UtcTimestamp> for u64 {
    fn from(timestamp: UtcTimestamp) -> Self {
        timestamp.0
    }
}

impl AddAssign<Duration> for UtcTimestamp {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.as_secs()
    }
}

impl Add<Duration> for UtcTimestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_secs())
    }
}
