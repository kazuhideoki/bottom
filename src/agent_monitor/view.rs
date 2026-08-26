use std::borrow::Cow;

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::{
    app::App,
    canvas::{
        Painter,
        components::time_series::{AxisBound, ChartScaling, GraphData},
    },
    components::time_series::GraphDrawCtx,
};

use super::state::{AgentFindingKind, AgentHistory, AgentMonitor, AgentSession};

impl Painter {
    pub fn draw_agent_dashboard(
        &self, f: &mut Frame<'_>, app_state: &mut App, draw_loc: Rect, widget_id: u64,
        is_overlay: bool,
    ) {
        f.buffer_mut()
            .set_style(draw_loc, self.styles.general_widget_style);

        let finding_height = if draw_loc.height >= 18 { 5 } else { 3 };
        let [summary_area, main_area, findings_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(finding_height),
        ])
        .areas(draw_loc);
        let [sessions_area, graph_area] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(main_area);
        let [cpu_area, rss_area] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(graph_area);

        self.draw_agent_summary(f, app_state, summary_area, is_overlay);
        self.draw_agent_sessions(f, app_state, sessions_area);
        self.draw_agent_graphs(f, app_state, cpu_area, rss_area);
        self.draw_agent_findings(f, app_state, findings_area);

        if !is_overlay
            && app_state.should_get_widget_bounds()
            && let Some(widget) = app_state.widget_map.get_mut(&widget_id)
        {
            widget.top_left_corner = Some((draw_loc.x, draw_loc.y));
            widget.bottom_right_corner =
                Some((draw_loc.x + draw_loc.width, draw_loc.y + draw_loc.height));
        }
    }

    fn draw_agent_summary(&self, f: &mut Frame<'_>, app_state: &App, area: Rect, is_overlay: bool) {
        let snapshot = &app_state.agent_monitor.snapshot;
        let hint = if is_overlay {
            " a/Esc: normal view "
        } else {
            " a: full-screen "
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.styles.border_type)
            .border_style(self.styles.highlighted_border_style)
            .title(Line::styled(
                " Agent Monitor ",
                self.styles.widget_title_style,
            ))
            .title(Line::styled(hint, self.styles.widget_title_style).right_aligned());
        let summary = Line::from(vec![
            Span::raw(format!(" roots: {}", snapshot.sessions.len())),
            Span::raw(format!("  Codex: {}", snapshot.codex_sessions)),
            Span::raw(format!("  Claude: {}", snapshot.claude_sessions)),
            Span::raw(format!("  CPU: {:.1}%", snapshot.total_cpu_usage_percent)),
            Span::raw(format!(
                "  ΣRSS: {}",
                format_bytes(snapshot.total_rss_bytes)
            )),
            Span::raw(format!("  proc: {}", snapshot.total_processes)),
            Span::styled(
                format!("  findings: {} ", snapshot.findings.len()),
                if snapshot.findings.is_empty() {
                    self.styles.text_style
                } else {
                    self.styles.invalid_query_style
                },
            ),
        ]);
        f.render_widget(
            Paragraph::new(summary)
                .block(block)
                .style(self.styles.text_style),
            area,
        );
    }

    fn draw_agent_sessions(&self, f: &mut Frame<'_>, app_state: &App, area: Rect) {
        let state = &app_state.agent_monitor;
        let available_lines = area.height.saturating_sub(2) as usize;
        let mut rows = Vec::new();

        if state.snapshot.sessions.is_empty() {
            rows.push(AgentTreeRow::new(
                AgentTreeRowKind::Session,
                " No Codex or Claude root processes detected.",
                self.styles.disabled_text_style,
            ));
        } else {
            for (index, session) in state.snapshot.sessions.iter().enumerate() {
                let selected = index == state.selected_session;
                let marker = if selected { "▶" } else { " " };
                let warning = if session.zombie_count > 0 {
                    format!("  Z:{}", session.zombie_count)
                } else {
                    String::new()
                };
                let line = format!(
                    "{marker} {:<6} #{:<6} {:>6.1}% {:>8} {:>3}p  {:>7}{warning}",
                    session.provider.label(),
                    session.key.root.pid,
                    session.cpu_usage_percent,
                    format_bytes(session.rss_bytes),
                    session.processes.len(),
                    format_duration(session.uptime),
                );
                rows.push(AgentTreeRow::new(
                    AgentTreeRowKind::Session,
                    line,
                    if selected {
                        self.styles.selected_text_style
                    } else {
                        self.styles.text_style
                    },
                ));

                if selected {
                    for process in session.processes.iter().skip(1) {
                        let indent = "  ".repeat(process.depth.saturating_sub(1));
                        let state_marker = if process.is_zombie() { " Z" } else { "" };
                        rows.push(AgentTreeRow::new(
                            AgentTreeRowKind::Process,
                            format!(
                                "  {indent}└─ {:<18} #{:<6} {:>5.1}% {:>8}{state_marker}",
                                process.name,
                                process.identity.pid,
                                process.cpu_usage_percent,
                                format_bytes(process.rss_bytes),
                            ),
                            if process.is_zombie() {
                                self.styles.invalid_query_style
                            } else {
                                self.styles.disabled_text_style
                            },
                        ));
                    }
                }
            }
        }

        let selected_row = state.selected_session.min(rows.len().saturating_sub(1));
        let viewport = agent_tree_viewport(rows.len(), selected_row, available_lines);
        let mut lines = Vec::with_capacity(available_lines);
        if viewport.start > 0 {
            lines.push(Line::styled(
                hidden_rows_label("↑", &rows[..viewport.start]),
                self.styles.disabled_text_style,
            ));
        }
        lines.extend(
            rows[viewport.start..viewport.end]
                .iter()
                .map(|row| row.line.clone()),
        );
        if viewport.end < rows.len() {
            lines.push(Line::styled(
                hidden_rows_label("↓", &rows[viewport.end..]),
                self.styles.disabled_text_style,
            ));
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.styles.border_type)
            .border_style(self.styles.border_style)
            .title(Line::styled(
                " Sessions / process tree (j/k) ",
                self.styles.widget_title_style,
            ));
        f.render_widget(
            Paragraph::new(lines)
                .block(block)
                .style(self.styles.text_style),
            area,
        );
    }

    fn draw_agent_graphs(
        &self, f: &mut Frame<'_>, app_state: &mut App, cpu_area: Rect, rss_area: Rect,
    ) {
        let AgentMonitor {
            snapshot,
            selected_session,
            histories,
            cpu_graph,
            rss_graph,
            ..
        } = &mut app_state.agent_monitor;
        let Some(session) = snapshot.sessions.get(*selected_session) else {
            self.draw_empty_agent_graph(f, cpu_area, " CPU — no selected session ");
            self.draw_empty_agent_graph(f, rss_area, " ΣRSS — no selected session ");
            return;
        };
        let Some(history) = histories.get(&session.key) else {
            self.draw_empty_agent_graph(f, cpu_area, " CPU — collecting history ");
            self.draw_empty_agent_graph(f, rss_area, " ΣRSS — collecting history ");
            return;
        };

        draw_cpu_graph(self, f, cpu_area, session, history, cpu_graph);
        draw_rss_graph(self, f, rss_area, session, history, rss_graph);
    }

    fn draw_empty_agent_graph(&self, f: &mut Frame<'_>, area: Rect, title: &'static str) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.styles.border_type)
            .border_style(self.styles.border_style)
            .title(Line::styled(title, self.styles.widget_title_style));
        f.render_widget(
            Paragraph::new(" Waiting for agent process data…")
                .block(block)
                .style(self.styles.disabled_text_style),
            area,
        );
    }

    fn draw_agent_findings(&self, f: &mut Frame<'_>, app_state: &App, area: Rect) {
        let findings = &app_state.agent_monitor.snapshot.findings;
        let available = area.height.saturating_sub(2) as usize;
        let lines = if findings.is_empty() {
            vec![Line::styled(
                " No zombie, detached, or sustained RSS growth signals.",
                self.styles.disabled_text_style,
            )]
        } else {
            findings
                .iter()
                .take(available)
                .map(|finding| {
                    let marker = match finding.kind {
                        AgentFindingKind::Zombie => "Z",
                        AgentFindingKind::Detached => "D",
                        AgentFindingKind::RssRising => "↑",
                    };
                    Line::styled(
                        format!(" {marker} {}", finding.message),
                        self.styles.invalid_query_style,
                    )
                })
                .collect()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(self.styles.border_type)
            .border_style(if findings.is_empty() {
                self.styles.border_style
            } else {
                self.styles.highlighted_border_style
            })
            .title(Line::styled(" Findings ", self.styles.widget_title_style));
        f.render_widget(
            Paragraph::new(lines)
                .block(block)
                .style(self.styles.text_style),
            area,
        );
    }
}

#[derive(Clone, Copy)]
enum AgentTreeRowKind {
    Session,
    Process,
}

struct AgentTreeRow {
    kind: AgentTreeRowKind,
    line: Line<'static>,
}

impl AgentTreeRow {
    fn new(
        kind: AgentTreeRowKind, content: impl Into<Line<'static>>, style: ratatui::style::Style,
    ) -> Self {
        Self {
            kind,
            line: content.into().style(style),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct AgentTreeViewport {
    start: usize,
    end: usize,
}

fn agent_tree_viewport(
    total_rows: usize, selected_row: usize, available_lines: usize,
) -> AgentTreeViewport {
    if total_rows <= available_lines {
        return AgentTreeViewport {
            start: 0,
            end: total_rows,
        };
    }
    if available_lines == 0 {
        return AgentTreeViewport { start: 0, end: 0 };
    }
    if available_lines < 3 {
        let start = selected_row.min(total_rows.saturating_sub(available_lines));
        return AgentTreeViewport {
            start,
            end: (start + available_lines).min(total_rows),
        };
    }

    // Keep up to two context rows above the selection. One line is reserved for
    // each overflow marker so the selected session itself never gets clipped.
    let preceding_rows = 2.min(available_lines - 3);
    let preferred_start = selected_row.saturating_sub(preceding_rows);
    let top_marker = usize::from(preferred_start > 0);
    let content_with_bottom_marker = available_lines - top_marker - 1;
    let preferred_end = preferred_start + content_with_bottom_marker;

    if preferred_end >= total_rows {
        // Near the bottom, backfill with earlier rows instead of leaving blank
        // space. Since total_rows > available_lines, a top marker is required.
        let start = total_rows - (available_lines - 1);
        AgentTreeViewport {
            start,
            end: total_rows,
        }
    } else {
        AgentTreeViewport {
            start: preferred_start,
            end: preferred_end,
        }
    }
}

fn hidden_rows_label(direction: &str, rows: &[AgentTreeRow]) -> String {
    let sessions = rows
        .iter()
        .filter(|row| matches!(row.kind, AgentTreeRowKind::Session))
        .count();
    let processes = rows.len() - sessions;
    match (sessions, processes) {
        (0, processes) => format!(" {direction} {processes} child processes hidden"),
        (sessions, 0) => format!(" {direction} {sessions} sessions hidden"),
        (sessions, processes) => {
            format!(" {direction} {sessions} sessions, {processes} child processes hidden")
        }
    }
}

fn draw_cpu_graph(
    painter: &Painter, f: &mut Frame<'_>, area: Rect, session: &AgentSession,
    history: &AgentHistory, graph: &mut crate::components::time_series::AutoYAxisTimeGraph,
) {
    let observed_max = graph
        .y_max(std::iter::once(&history.cpu), &history.time)
        .max(100.0);
    let upper = (observed_max * 1.05).ceil();
    let labels = vec![Cow::Borrowed("0%"), Cow::Owned(format!("{upper:.0}%"))];
    let data = vec![
        GraphData::default()
            .name(format!("current {:.1}%", session.cpu_usage_percent).into())
            .style(painter.styles.avg_cpu_colour)
            .time(&history.time)
            .values(&history.cpu),
    ];
    graph.draw(
        f,
        area,
        graph_context(
            painter,
            format!(" CPU — {} #{} ", session.provider, session.key.root.pid).into(),
        ),
        AxisBound::Max(upper),
        &labels,
        ChartScaling::Linear,
        data,
    );
}

fn draw_rss_graph(
    painter: &Painter, f: &mut Frame<'_>, area: Rect, session: &AgentSession,
    history: &AgentHistory, graph: &mut crate::components::time_series::AutoYAxisTimeGraph,
) {
    let observed_max = graph
        .y_max(std::iter::once(&history.rss_mib), &history.time)
        .max(1.0);
    let upper = (observed_max * 1.10).ceil();
    let labels = vec![Cow::Borrowed("0"), Cow::Owned(format_mib_axis(upper))];
    let data = vec![
        GraphData::default()
            .name(format!("current {}", format_bytes(session.rss_bytes)).into())
            .style(painter.styles.ram_style)
            .time(&history.time)
            .values(&history.rss_mib),
    ];
    graph.draw(
        f,
        area,
        graph_context(
            painter,
            format!(" ΣRSS — {} #{} ", session.provider, session.key.root.pid).into(),
        ),
        AxisBound::Max(upper),
        &labels,
        ChartScaling::Linear,
        data,
    );
}

fn graph_context<'a>(painter: &Painter, title: Cow<'a, str>) -> GraphDrawCtx<'a> {
    GraphDrawCtx {
        title,
        border_style: painter.styles.border_style,
        title_style: painter.styles.widget_title_style,
        graph_style: painter.styles.graph_style,
        general_widget_style: painter.styles.general_widget_style,
        border_type: painter.styles.border_type,
        marker: ratatui::symbols::Marker::Braille,
        hide_x_labels: false,
        is_selected: false,
        is_expanded: false,
        legend_position: None,
        legend_constraints: None,
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1}GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.0}MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.0}KiB", bytes / KIB)
    } else {
        format!("{bytes:.0}B")
    }
}

fn format_mib_axis(mib: f64) -> String {
    if mib >= 1024.0 {
        format!("{:.1}GiB", mib / 1024.0)
    } else {
        format!("{mib:.0}MiB")
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 86_400 {
        format!("{}d{:02}h", seconds / 86_400, (seconds / 3_600) % 24)
    } else if seconds >= 3_600 {
        format!("{}h{:02}m", seconds / 3_600, (seconds / 60) % 60)
    } else if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_tree_does_not_scroll_when_every_row_fits() {
        assert_eq!(
            agent_tree_viewport(6, 4, 15),
            AgentTreeViewport { start: 0, end: 6 }
        );
    }

    #[test]
    fn agent_tree_keeps_selection_visible_when_rows_overflow() {
        let viewport = agent_tree_viewport(40, 20, 14);
        assert!(viewport.start <= 20 && 20 < viewport.end);
        assert_eq!(viewport.start, 18);
        assert_eq!(viewport.end, 30);
    }

    #[test]
    fn agent_tree_backfills_rows_near_the_bottom() {
        assert_eq!(
            agent_tree_viewport(10, 9, 6),
            AgentTreeViewport { start: 5, end: 10 }
        );
    }
}
