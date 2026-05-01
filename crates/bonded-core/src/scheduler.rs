#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId(pub u32);

pub trait Scheduler {
    fn choose_path(&mut self, available_paths: &[PathId]) -> Option<PathId>;
}

#[derive(Debug, Default)]
pub struct RoundRobinScheduler {
    next_index: usize,
}

impl Scheduler for RoundRobinScheduler {
    fn choose_path(&mut self, available_paths: &[PathId]) -> Option<PathId> {
        if available_paths.is_empty() {
            return None;
        }
        let idx = self.next_index % available_paths.len();
        self.next_index = self.next_index.wrapping_add(1);
        Some(available_paths[idx])
    }
}

#[derive(Debug, Default)]
pub struct ActiveStandbyScheduler;

impl Scheduler for ActiveStandbyScheduler {
    fn choose_path(&mut self, available_paths: &[PathId]) -> Option<PathId> {
        available_paths.first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{PathId, RoundRobinScheduler, Scheduler};

    #[test]
    fn round_robin_rotates_paths() {
        let mut rr = RoundRobinScheduler::default();
        let paths = [PathId(1), PathId(2)];
        assert_eq!(rr.choose_path(&paths), Some(PathId(1)));
        assert_eq!(rr.choose_path(&paths), Some(PathId(2)));
    }
}
