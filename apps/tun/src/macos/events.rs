//! Existing redacted lifecycle events share the bounded persistent writer.
pub(super) fn record(event: &str) {
    record_at(rtrust_journal::Level::Debug, event);
}
pub(super) fn record_at(level: rtrust_journal::Level, event: &str) {
    crate::journal(level, event);
}
