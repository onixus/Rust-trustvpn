//! Shared UI ownership of a diagnostic: cancellation, freshness and edited export.
use crate::diagnostics::{Report, Verdict};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    sequence: u64,
    epoch: u64,
    generation: u64,
}
struct Stored {
    ticket: Ticket,
    report: Report,
}
#[derive(Default)]
pub struct Frontend {
    sequence: u64,
    task: Option<tokio::task::AbortHandle>,
    last_started: Option<Instant>,
    stored: Option<Stored>,
    edited: Option<String>,
}
#[derive(Serialize)]
pub struct View {
    pub running: bool,
    pub historical: bool,
    pub age_ms: Option<u64>,
    pub summary: Option<String>,
    pub verdict: Option<Verdict>,
    pub report: Option<Report>,
    pub export: Option<String>,
    pub export_edited: bool,
}
impl Drop for Frontend {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl Frontend {
    pub fn cancel(&mut self) {
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
    pub fn begin(&mut self, epoch: u64, generation: u64) -> Result<Ticket, &'static str> {
        if self
            .last_started
            .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
        {
            return Err("Wait five seconds between checks");
        }
        self.cancel();
        self.last_started = Some(Instant::now());
        Ok(Ticket {
            sequence: self.sequence,
            epoch,
            generation,
        })
    }
    pub fn own(&mut self, task: tokio::task::AbortHandle) {
        self.task = Some(task);
    }
    pub fn finish(&mut self, ticket: Ticket, epoch: u64, generation: u64, report: Report) -> bool {
        if ticket.sequence != self.sequence
            || ticket.epoch != epoch
            || ticket.generation != generation
            || report.lifecycle.generation != generation
        {
            return false;
        }
        self.task = None;
        self.stored = Some(Stored { ticket, report });
        true
    }
    pub fn view(&self, epoch: u64, generation: Option<u64>, now: u64) -> View {
        let report = self.stored.as_ref().map(|s| s.report.clone());
        let age = report
            .as_ref()
            .map(|r| now.saturating_sub(r.finished_at_ms));
        let historical = self.stored.as_ref().is_some_and(|s| {
            s.ticket.sequence != self.sequence
                || s.ticket.epoch != epoch
                || generation != Some(s.ticket.generation)
                || now < s.report.finished_at_ms
                || age.is_none_or(|ms| ms > 6_000)
        });
        View {
            running: self.task.as_ref().is_some_and(|t| !t.is_finished()),
            historical,
            age_ms: age,
            summary: report.as_ref().map(Report::summary),
            verdict: report.as_ref().map(Report::verdict),
            export: self
                .edited
                .clone()
                .or_else(|| report.as_ref().map(Report::redacted_json)),
            export_edited: self.edited.is_some(),
            report,
        }
    }
    pub fn edit_export(&mut self, text: String) -> Result<(), &'static str> {
        if self.stored.is_none() {
            return Err("Run a diagnostic first");
        }
        if text.len() > 64 * 1024 {
            return Err("Export exceeds 64 KiB");
        }
        self.edited = Some(text);
        Ok(())
    }
    pub fn replace_export(&mut self) {
        self.edited = None;
    }
    pub fn current_report(&self, epoch: u64, generation: u64, now: u64) -> Option<Report> {
        let view = self.view(epoch, Some(generation), now);
        (!view.historical).then_some(view.report).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_control::observations::{Mode, Snapshot};
    fn report(generation: u64) -> Report {
        let mut s = Snapshot::unknown(Mode::Full);
        s.generation = generation;
        let mut r = Report::new(s);
        r.finished_at_ms = 1_000;
        r
    }
    #[test]
    fn cancellation_and_connection_changes_reject_late_results() {
        let mut ui = Frontend::default();
        let ticket = ui.begin(1, 5).unwrap();
        assert!(!ui.finish(ticket, 2, 5, report(5)));
        assert!(!ui.finish(ticket, 1, 6, report(5)));
        ui.cancel();
        assert!(!ui.finish(ticket, 1, 5, report(5)));
        assert!(ui.view(1, Some(5), 1_000).report.is_none());
    }
    #[test]
    fn edited_export_survives_checks_and_history_is_explicit() {
        let mut ui = Frontend::default();
        let ticket = ui.begin(1, 5).unwrap();
        assert!(ui.finish(ticket, 1, 5, report(5)));
        ui.edit_export("redacted by user".into()).unwrap();
        let mut next = report(5);
        next.finished_at_ms = 2_000;
        assert!(ui.finish(ticket, 1, 5, next));
        assert_eq!(
            ui.view(1, Some(5), 2_001).export.as_deref(),
            Some("redacted by user")
        );
        assert!(ui.view(2, Some(5), 2_001).historical);
        assert!(ui.view(1, Some(6), 2_001).historical);
        assert!(ui.view(1, Some(5), 9_000).historical);
        ui.replace_export();
        assert!(!ui.view(1, Some(5), 2_001).export_edited);
        assert!(ui.edit_export("x".repeat(65_537)).is_err());
    }
    #[test]
    fn destination_change_cannot_reset_cooldown() {
        let mut ui = Frontend::default();
        ui.begin(1, 5).unwrap();
        ui.cancel();
        assert!(ui.begin(1, 5).is_err());
    }
}
