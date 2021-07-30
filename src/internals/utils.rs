use std::time::SystemTime;

/// Gets the current Unix-Timestamp
pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Current time should always be after the Unix-Epoch")
        .as_secs()
}
