pub use zmax_redis::ClusterSyncEvent;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_events_reexport() {
        let ev = ClusterSyncEvent::PurgeAll;
        assert_eq!(ev.to_wire_string(), "purge:*");
    }
}
