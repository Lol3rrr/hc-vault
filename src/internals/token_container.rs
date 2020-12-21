/// The internal Container for a Token, which can be read and updated
/// from multiple threads at a time
///
/// Note: Certain access still need to be synchronized, like when updating
/// the Token, you should not read from it at the same time as there is a
/// very small window in which you could have a data race and therefor read
/// incorrect memory or an incorrect pointer
pub struct TokenContainer {
    token: std::sync::atomic::AtomicPtr<String>,
    start: std::sync::atomic::AtomicU64,
    duration: std::sync::atomic::AtomicU64,
    renewable: std::sync::atomic::AtomicBool,
}

impl TokenContainer {
    /// Used to obtain a new TokenContainer with empty/null values
    pub fn new() -> TokenContainer {
        let boxed_empty = Box::new(String::from(""));
        let empty_ptr = Box::into_raw(boxed_empty);

        TokenContainer {
            token: std::sync::atomic::AtomicPtr::new(empty_ptr),
            start: std::sync::atomic::AtomicU64::new(0),
            duration: std::sync::atomic::AtomicU64::new(0),
            renewable: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Returns the start time for the Token
    pub fn get_start(&self) -> u64 {
        self.start.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the duration for the Token
    pub fn get_duration(&self) -> u64 {
        self.duration.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the renewable status for the Token
    pub fn get_renewable(&self) -> bool {
        self.renewable.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the Token itself
    ///
    /// Problem:
    /// There could be a Data Race if this access is not synchronized in any
    /// way, because there could be a Ptr-Swap + Drop in another thread after
    /// this thread has read the Ptr itself and before it has actually cloned
    /// the Data where the Ptr was pointing at.
    ///
    /// Safety:
    /// This Operation relies on the fact that while the token is being loaded,
    /// it is not going to be swapped out by another thread.
    /// After this function is finished the String is still valid to use,
    /// so only during it's execution is a data race present. However multiple
    /// threads can still read this token at the same time with no problems as
    /// long as it is not swapped out
    pub fn get_token(&self) -> Option<String> {
        let raw_token = self.token.load(std::sync::atomic::Ordering::SeqCst);
        match unsafe { raw_token.as_ref() } {
            None => None,
            Some(s) => Some(s.clone()),
        }
    }

    /// Updates the internal Start time for the Token
    pub fn set_start(&self, new_start: u64) {
        self.start
            .store(new_start, std::sync::atomic::Ordering::SeqCst);
    }

    /// Updates the internal Duration for the Token
    pub fn set_duration(&self, new_duration: u64) {
        self.duration
            .store(new_duration, std::sync::atomic::Ordering::SeqCst);
    }

    /// Updates the internal renewable status for the Token
    pub fn set_renewable(&self, new_renewable: bool) {
        self.renewable
            .store(new_renewable, std::sync::atomic::Ordering::SeqCst)
    }

    /// Updates the internal token itself
    ///
    /// Safety:
    /// This access needs to be synchronized externally to make sure that
    /// no other thread is trying to read the token while it is updated in
    /// this function. Internally this is usually garantued by the fact that
    /// the Session is blocking while the session is being updated and therefor
    /// no other operations can take place and subsequentially also no reads
    /// of the actual token
    pub fn set_token(&self, token: String) {
        let boxed = Box::new(token);
        let new_ptr = Box::into_raw(boxed);

        let old_ptr = self
            .token
            .swap(new_ptr, std::sync::atomic::Ordering::SeqCst);

        // This actually drops the old token, which is an unsafe operation to do
        // because there is no direct reference counting and theoretically there
        // could be another thread that is currently trying to copy the old token.
        // However this is mitigated by the fact, that this function call is
        // synchronized by the caller and therefor no other thread can actually
        // read the old token, while it is being dropped here.
        unsafe {
            drop(Box::from_raw(old_ptr));
        }
    }
}
