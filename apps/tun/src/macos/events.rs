//! Existing redacted lifecycle events share the bounded persistent writer.
pub(super) fn record(event: &str) {
    #[cfg(not(test))]
    rtrust_journal::service().lifecycle(event);
    #[cfg(test)]
    let _ = event;
}
