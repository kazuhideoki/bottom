//! Codex/Claude process monitoring boundary.

#[cfg(feature = "agent-monitor")]
mod state;
#[cfg(feature = "agent-monitor")]
mod view;

#[cfg(feature = "agent-monitor")]
pub(crate) use state::AgentMonitor;

#[cfg(not(feature = "agent-monitor"))]
pub(crate) struct AgentMonitor;

#[cfg(not(feature = "agent-monitor"))]
impl AgentMonitor {
    pub(crate) fn new(
        _config: &crate::app::AppConfigFields, _overlay_active: bool, _layout_present: bool,
    ) -> Self {
        Self
    }

    pub(crate) fn is_overlay_active(&self) -> bool {
        false
    }

    pub(crate) fn collection_enabled(&self) -> bool {
        false
    }

    pub(crate) fn toggle_overlay(&mut self) {}

    pub(crate) fn close_overlay(&mut self) -> bool {
        false
    }

    pub(crate) fn reset(&mut self) {}

    pub(crate) fn refresh(
        &mut self, _process_data: &crate::app::data::ProcessData, _at: std::time::Instant,
    ) {
    }

    pub(crate) fn prune(&mut self, _max_age: std::time::Duration) {}

    pub(crate) fn increment_selection(&mut self, _amount: i64) {}

    pub(crate) fn select_first(&mut self) {}

    pub(crate) fn select_last(&mut self) {}
}

#[cfg(not(feature = "agent-monitor"))]
impl crate::canvas::Painter {
    pub(crate) fn draw_agent_dashboard(
        &self, _f: &mut ratatui::Frame<'_>, _app_state: &mut crate::app::App,
        _draw_loc: ratatui::layout::Rect, _widget_id: u64, _is_overlay: bool,
    ) {
    }
}
