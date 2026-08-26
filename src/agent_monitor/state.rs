//! Agent-focused process classification, aggregation, and history.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    time::{Duration, Instant},
};

use timeless::data::ChunkedData;

use crate::{
    app::{AppConfigFields, data::ProcessData},
    collection::processes::{Pid, ProcessHarvest},
    components::time_series::{AutoYAxisTimeGraph, TimeseriesConfig},
};

const MIN_RSS_GROWTH_WINDOW: Duration = Duration::from_secs(60);
const MIN_RSS_GROWTH_BYTES: u64 = 64 * 1024 * 1024;
const MIN_RSS_GROWTH_RATIO: f64 = 1.20;
const PROCESS_START_TOLERANCE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum AgentProvider {
    Codex,
    Claude,
}

impl AgentProvider {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude",
        }
    }
}

impl fmt::Display for AgentProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ProcessIdentity {
    pub(super) pid: Pid,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct AgentSessionKey {
    pub(super) root: ProcessIdentity,
}

#[derive(Clone, Debug)]
pub(super) struct AgentProcess {
    pub(super) identity: ProcessIdentity,
    pub(super) name: String,
    pub(super) depth: usize,
    pub(super) cpu_usage_percent: f32,
    pub(super) rss_bytes: u64,
    pub(super) state: &'static str,
    pub(super) state_char: char,
}

impl AgentProcess {
    fn from_harvest(process: &ProcessHarvest, identity: ProcessIdentity, depth: usize) -> Self {
        Self {
            identity,
            name: process.name.clone(),
            depth,
            cpu_usage_percent: process.cpu_usage_percent,
            rss_bytes: process.mem_usage,
            state: process.process_state.0,
            state_char: process.process_state.1,
        }
    }

    pub(super) fn is_zombie(&self) -> bool {
        self.state.eq_ignore_ascii_case("zombie") || self.state_char == 'Z'
    }
}

#[derive(Clone, Debug)]
pub(super) struct AgentSession {
    pub(super) key: AgentSessionKey,
    pub(super) provider: AgentProvider,
    pub(super) cpu_usage_percent: f32,
    pub(super) rss_bytes: u64,
    pub(super) uptime: Duration,
    pub(super) processes: Vec<AgentProcess>,
    pub(super) zombie_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AgentFindingKind {
    Zombie,
    Detached,
    RssRising,
}

#[derive(Clone, Debug)]
pub(super) struct AgentFinding {
    pub(super) kind: AgentFindingKind,
    pub(super) message: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct AgentSnapshot {
    pub(super) sessions: Vec<AgentSession>,
    pub(super) findings: Vec<AgentFinding>,
    pub(super) total_cpu_usage_percent: f32,
    pub(super) total_rss_bytes: u64,
    pub(super) total_processes: usize,
    pub(super) codex_sessions: usize,
    pub(super) claude_sessions: usize,
}

#[derive(Clone, Debug, Default)]
pub(super) struct AgentHistory {
    pub(super) time: Vec<Instant>,
    pub(super) cpu: ChunkedData<f64>,
    pub(super) rss_mib: ChunkedData<f64>,
}

impl AgentHistory {
    fn push(&mut self, at: Instant, session: &AgentSession) {
        if self.time.last() == Some(&at) {
            return;
        }

        self.time.push(at);
        self.cpu.push(session.cpu_usage_percent.into());
        self.rss_mib
            .push(session.rss_bytes as f64 / (1024.0 * 1024.0));
    }

    fn rss_growth_bytes(&self) -> Option<u64> {
        let (first_time, last_time) = (self.time.first()?, self.time.last()?);
        if last_time.duration_since(*first_time) < MIN_RSS_GROWTH_WINDOW {
            return None;
        }

        let first = self.rss_mib.first()? * 1024.0 * 1024.0;
        let last = self.rss_mib.last()? * 1024.0 * 1024.0;
        let growth = last - first;
        if first > 0.0
            && growth >= MIN_RSS_GROWTH_BYTES as f64
            && last / first >= MIN_RSS_GROWTH_RATIO
        {
            Some(growth as u64)
        } else {
            None
        }
    }

    fn prune(&mut self, max_age: Duration, now: Instant) {
        let end = self
            .time
            .partition_point(|then| now.duration_since(*then) > max_age);
        if end == 0 {
            return;
        }

        self.time.drain(0..end);
        let inclusive_end = end - 1;
        let _ = self.cpu.prune_and_shrink_to_fit(inclusive_end);
        let _ = self.rss_mib.prune_and_shrink_to_fit(inclusive_end);
    }

    fn is_empty(&self) -> bool {
        self.time.is_empty()
    }
}

pub(crate) struct AgentMonitor {
    overlay_active: bool,
    layout_present: bool,
    pub(super) snapshot: AgentSnapshot,
    pub(super) selected_session: usize,
    pub(super) histories: HashMap<AgentSessionKey, AgentHistory>,
    pub(super) cpu_graph: AutoYAxisTimeGraph,
    pub(super) rss_graph: AutoYAxisTimeGraph,
    previous_owner: HashMap<ProcessIdentity, AgentSessionKey>,
    known_providers: HashMap<AgentSessionKey, AgentProvider>,
    observed_identities: HashMap<Pid, ObservedIdentity>,
    refresh_generation: u64,
    next_process_generation: u64,
}

#[derive(Clone, Copy)]
struct ObservedIdentity {
    identity: ProcessIdentity,
    last_refresh: u64,
    last_uptime: Duration,
    estimated_start: Option<Instant>,
}

impl AgentMonitor {
    pub(crate) fn new(
        config: &AppConfigFields, overlay_active: bool, layout_present: bool,
    ) -> Self {
        let graph_config = TimeseriesConfig {
            time_interval: config.time_interval,
            retention_ms: config.retention_ms,
            autohide_time: config.autohide_time,
            default_time_value: config.default_time_value,
        };

        Self {
            overlay_active,
            layout_present,
            snapshot: AgentSnapshot::default(),
            selected_session: 0,
            histories: HashMap::new(),
            cpu_graph: AutoYAxisTimeGraph::new(graph_config, None),
            rss_graph: AutoYAxisTimeGraph::new(graph_config, None),
            previous_owner: HashMap::new(),
            known_providers: HashMap::new(),
            observed_identities: HashMap::new(),
            refresh_generation: 0,
            next_process_generation: 0,
        }
    }

    pub(crate) fn is_overlay_active(&self) -> bool {
        self.overlay_active
    }

    pub(crate) fn collection_enabled(&self) -> bool {
        self.layout_present || self.overlay_active
    }

    pub(crate) fn toggle_overlay(&mut self) {
        self.overlay_active = !self.overlay_active;
    }

    pub(crate) fn close_overlay(&mut self) -> bool {
        std::mem::take(&mut self.overlay_active)
    }

    pub fn reset(&mut self) {
        self.snapshot = AgentSnapshot::default();
        self.selected_session = 0;
        self.histories.clear();
        self.previous_owner.clear();
        self.known_providers.clear();
        self.observed_identities.clear();
        self.refresh_generation = 0;
        self.next_process_generation = 0;
        self.cpu_graph.state_mut().reset_zoom();
        self.rss_graph.state_mut().reset_zoom();
    }

    pub fn refresh(&mut self, process_data: &ProcessData, at: Instant) {
        let selected_key = self.selected().map(|session| session.key);
        let identities = self.refresh_process_identities(process_data, at);
        let provider_by_pid = process_data
            .process_harvest
            .values()
            .filter_map(|process| detect_provider(process).map(|provider| (process.pid, provider)))
            .collect::<HashMap<_, _>>();

        let mut roots = provider_by_pid
            .iter()
            .filter_map(|(&pid, &provider)| {
                (!has_agent_ancestor(pid, process_data, &provider_by_pid))
                    .then_some((pid, provider))
            })
            .collect::<Vec<_>>();
        roots.sort_unstable_by_key(|(pid, provider)| (*provider, *pid));

        let mut current_owner = HashMap::new();
        let mut sessions = roots
            .into_iter()
            .filter_map(|(root_pid, provider)| {
                build_session(
                    root_pid,
                    provider,
                    process_data,
                    &identities,
                    &mut current_owner,
                )
            })
            .collect::<Vec<_>>();
        sessions.sort_unstable_by_key(|session| (session.provider, session.key.root.pid));

        let mut findings = Vec::new();
        for session in &sessions {
            self.known_providers.insert(session.key, session.provider);
            for process in session
                .processes
                .iter()
                .filter(|process| process.is_zombie())
            {
                findings.push(AgentFinding {
                    kind: AgentFindingKind::Zombie,
                    message: format!(
                        "ZOMBIE pid {} ({}) under {} #{}",
                        process.identity.pid, process.name, session.provider, session.key.root.pid
                    ),
                });
            }
        }

        // Preserve prior ownership for descendants that outlive an agent root and
        // get re-parented. This is a best-effort cleanup signal, not proof of a bug.
        for process in process_data.process_harvest.values() {
            let Some(identity) = identities.get(&process.pid).copied() else {
                continue;
            };
            if current_owner.contains_key(&identity) {
                continue;
            }

            if let Some(previous_session) = self.previous_owner.get(&identity).copied()
                && let Some(provider) = self.known_providers.get(&previous_session).copied()
            {
                current_owner.insert(identity, previous_session);
                findings.push(AgentFinding {
                    kind: AgentFindingKind::Detached,
                    message: format!(
                        "DETACHED pid {} ({}) from ended {} #{}",
                        process.pid, process.name, provider, previous_session.root.pid
                    ),
                });
            }
        }

        for session in &sessions {
            let history = self.histories.entry(session.key).or_default();
            history.push(at, session);
            if let Some(growth) = history.rss_growth_bytes() {
                findings.push(AgentFinding {
                    kind: AgentFindingKind::RssRising,
                    message: format!(
                        "RSS rising +{} MiB for {} #{} (not a leak verdict)",
                        growth / (1024 * 1024),
                        session.provider,
                        session.key.root.pid
                    ),
                });
            }
        }

        let total_cpu_usage_percent = sessions
            .iter()
            .map(|session| session.cpu_usage_percent)
            .sum();
        let total_rss_bytes = sessions.iter().map(|session| session.rss_bytes).sum();
        let total_processes = sessions.iter().map(|session| session.processes.len()).sum();
        let codex_sessions = sessions
            .iter()
            .filter(|session| session.provider == AgentProvider::Codex)
            .count();
        let claude_sessions = sessions
            .iter()
            .filter(|session| session.provider == AgentProvider::Claude)
            .count();

        self.snapshot = AgentSnapshot {
            sessions,
            findings,
            total_cpu_usage_percent,
            total_rss_bytes,
            total_processes,
            codex_sessions,
            claude_sessions,
        };
        self.previous_owner = current_owner;

        self.selected_session = selected_key
            .and_then(|key| {
                self.snapshot
                    .sessions
                    .iter()
                    .position(|session| session.key == key)
            })
            .unwrap_or_else(|| {
                self.selected_session
                    .min(self.snapshot.sessions.len().saturating_sub(1))
            });
    }

    pub fn prune(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.histories.retain(|_, history| {
            history.prune(max_age, now);
            !history.is_empty()
        });
    }

    fn refresh_process_identities(
        &mut self, process_data: &ProcessData, at: Instant,
    ) -> HashMap<Pid, ProcessIdentity> {
        self.refresh_generation = self.refresh_generation.saturating_add(1);
        let current_refresh = self.refresh_generation;
        let mut identities = HashMap::default();

        for process in process_data.process_harvest.values() {
            let previous = self.observed_identities.get(&process.pid).copied();
            let estimated_start = at.checked_sub(process.time);
            let is_continuous = previous.is_some_and(|observed| {
                observed.last_refresh.saturating_add(1) == current_refresh
                    && process.time >= observed.last_uptime
                    && observed.estimated_start.zip(estimated_start).is_some_and(
                        |(previous, current)| {
                            instant_distance(previous, current) <= PROCESS_START_TOLERANCE
                        },
                    )
            });
            let identity = if is_continuous {
                previous.expect("continuous identity must exist").identity
            } else {
                let identity = ProcessIdentity {
                    pid: process.pid,
                    generation: self.next_process_generation,
                };
                self.next_process_generation = self.next_process_generation.saturating_add(1);
                identity
            };

            self.observed_identities.insert(
                process.pid,
                ObservedIdentity {
                    identity,
                    last_refresh: current_refresh,
                    last_uptime: process.time,
                    estimated_start,
                },
            );
            identities.insert(process.pid, identity);
        }

        self.observed_identities
            .retain(|_, observed| observed.last_refresh == current_refresh);
        identities
    }

    pub(super) fn selected(&self) -> Option<&AgentSession> {
        self.snapshot.sessions.get(self.selected_session)
    }

    pub fn increment_selection(&mut self, amount: i64) {
        let len = self.snapshot.sessions.len();
        if len == 0 {
            self.selected_session = 0;
            return;
        }

        self.selected_session = if amount.is_negative() {
            self.selected_session
                .saturating_sub(amount.unsigned_abs() as usize)
        } else {
            self.selected_session
                .saturating_add(amount as usize)
                .min(len - 1)
        };
    }

    pub fn select_first(&mut self) {
        self.selected_session = 0;
    }

    pub fn select_last(&mut self) {
        self.selected_session = self.snapshot.sessions.len().saturating_sub(1);
    }
}

fn instant_distance(left: Instant, right: Instant) -> Duration {
    if left >= right {
        left.duration_since(right)
    } else {
        right.duration_since(left)
    }
}

fn has_agent_ancestor(
    pid: Pid, process_data: &ProcessData, provider_by_pid: &HashMap<Pid, AgentProvider>,
) -> bool {
    let mut current_pid = pid;
    let mut visited = HashSet::new();
    while visited.insert(current_pid) {
        let Some(parent_pid) = process_data
            .process_harvest
            .get(&current_pid)
            .and_then(|process| process.parent_pid)
        else {
            return false;
        };

        if provider_by_pid.contains_key(&parent_pid) {
            return true;
        }
        current_pid = parent_pid;
    }
    false
}

fn build_session(
    root_pid: Pid, provider: AgentProvider, process_data: &ProcessData,
    identities: &HashMap<Pid, ProcessIdentity>,
    owner: &mut HashMap<ProcessIdentity, AgentSessionKey>,
) -> Option<AgentSession> {
    let root = process_data.process_harvest.get(&root_pid)?;
    let key = AgentSessionKey {
        root: *identities.get(&root_pid)?,
    };

    let mut processes = Vec::new();
    let mut stack = vec![(root_pid, 0_usize)];
    let mut visited = HashSet::new();
    while let Some((pid, depth)) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        let Some(process) = process_data.process_harvest.get(&pid) else {
            continue;
        };

        let identity = *identities.get(&pid)?;
        owner.insert(identity, key);
        processes.push(AgentProcess::from_harvest(process, identity, depth));

        if let Some(children) = process_data.process_parent_mapping.get(&pid) {
            let mut children = children.clone();
            children.sort_unstable();
            stack.extend(children.into_iter().rev().map(|child| (child, depth + 1)));
        }
    }

    let cpu_usage_percent = processes
        .iter()
        .map(|process| process.cpu_usage_percent)
        .sum();
    let rss_bytes = processes.iter().map(|process| process.rss_bytes).sum();
    let zombie_count = processes
        .iter()
        .filter(|process| process.is_zombie())
        .count();

    Some(AgentSession {
        key,
        provider,
        cpu_usage_percent,
        rss_bytes,
        uptime: root.time,
        processes,
        zombie_count,
    })
}

fn detect_provider(process: &ProcessHarvest) -> Option<AgentProvider> {
    let name = process.name.trim().to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    match name {
        "codex" | "codex-cli" => return Some(AgentProvider::Codex),
        "claude" | "claude-code" => return Some(AgentProvider::Claude),
        _ => {}
    }

    // Claude Code is commonly launched by a JS runtime. Limit command-based
    // matching to runtime processes so prompt text cannot create false roots.
    if matches!(name, "node" | "nodejs" | "bun" | "deno") {
        let command = process.command.to_ascii_lowercase();
        if command.contains("@anthropic-ai/claude-code")
            || command
                .split_whitespace()
                .take(3)
                .any(|part| executable_basename(part) == "claude")
        {
            return Some(AgentProvider::Claude);
        }
        if command
            .split_whitespace()
            .take(3)
            .any(|part| executable_basename(part) == "codex")
        {
            return Some(AgentProvider::Codex);
        }
    }

    None
}

fn executable_basename(value: &str) -> &str {
    value
        .trim_matches(['\'', '"'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: Pid, ppid: Option<Pid>, name: &str, cpu: f32, rss: u64) -> ProcessHarvest {
        ProcessHarvest {
            pid,
            parent_pid: ppid,
            name: name.to_string(),
            command: name.to_string(),
            cpu_usage_percent: cpu,
            mem_usage: rss,
            time: Duration::from_secs(60),
            ..ProcessHarvest::default()
        }
    }

    fn process_data(processes: Vec<ProcessHarvest>) -> ProcessData {
        ProcessData::from_harvest_for_test(processes)
    }

    fn config() -> AppConfigFields {
        AppConfigFields {
            time_interval: 15_000,
            retention_ms: 600_000,
            default_time_value: 60_000,
            ..AppConfigFields::default()
        }
    }

    #[test]
    fn detects_and_aggregates_agent_tree() {
        let data = process_data(vec![
            process(10, Some(1), "codex", 10.0, 100),
            process(11, Some(10), "zsh", 5.0, 200),
            process(12, Some(11), "cargo", 2.0, 300),
            process(20, Some(1), "Claude", 3.0, 400),
        ]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(&data, Instant::now());

        assert_eq!(state.snapshot.sessions.len(), 2);
        assert_eq!(state.snapshot.codex_sessions, 1);
        assert_eq!(state.snapshot.claude_sessions, 1);
        let codex = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.provider == AgentProvider::Codex)
            .unwrap();
        assert_eq!(codex.processes.len(), 3);
        assert_eq!(codex.cpu_usage_percent, 17.0);
        assert_eq!(codex.rss_bytes, 600);
        assert_eq!(codex.processes[2].depth, 2);
    }

    #[test]
    fn nested_agent_process_is_part_of_top_level_root() {
        let data = process_data(vec![
            process(10, Some(1), "codex", 1.0, 10),
            process(11, Some(10), "claude", 1.0, 10),
        ]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(&data, Instant::now());

        assert_eq!(state.snapshot.sessions.len(), 1);
        assert_eq!(state.snapshot.sessions[0].processes.len(), 2);
    }

    #[test]
    fn reports_zombie_and_detached_descendant() {
        let mut root = process(10, Some(1), "codex", 1.0, 10);
        root.process_state = ("Runnable", 'R');
        let mut child = process(11, Some(10), "node", 1.0, 10);
        child.process_state = ("Zombie", 'Z');

        let mut state = AgentMonitor::new(&config(), false, false);
        let now = Instant::now();
        state.refresh(&process_data(vec![root, child.clone()]), now);
        assert!(
            state
                .snapshot
                .findings
                .iter()
                .any(|finding| finding.kind == AgentFindingKind::Zombie)
        );

        child.parent_pid = Some(1);
        state.refresh(&process_data(vec![child]), now + Duration::from_secs(1));
        assert!(
            state
                .snapshot
                .findings
                .iter()
                .any(|finding| finding.kind == AgentFindingKind::Detached)
        );
    }

    #[test]
    fn runtime_command_match_is_limited_to_runtime_processes() {
        let mut prompt = process(1, None, "zsh", 0.0, 0);
        prompt.command = "zsh -c please inspect codex".to_string();
        let mut node = process(2, None, "node", 0.0, 0);
        node.command = "/usr/bin/node /opt/@anthropic-ai/claude-code/cli.js".to_string();

        assert_eq!(detect_provider(&prompt), None);
        assert_eq!(detect_provider(&node), Some(AgentProvider::Claude));
    }

    #[test]
    fn sustained_rss_growth_is_reported_as_a_signal() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![process(10, Some(1), "codex", 1.0, 100 * 1024 * 1024)]),
            now,
        );
        let mut grown = process(10, Some(1), "codex", 1.0, 180 * 1024 * 1024);
        grown.time = Duration::from_secs(121);
        state.refresh(&process_data(vec![grown]), now + Duration::from_secs(61));

        assert!(state.snapshot.findings.iter().any(|finding| {
            finding.kind == AgentFindingKind::RssRising
                && finding.message.contains("not a leak verdict")
        }));
    }

    #[test]
    fn reused_pid_does_not_inherit_session_history() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        let first = process(10, Some(1), "codex", 1.0, 100);
        state.refresh(&process_data(vec![first]), now);
        let first_key = state.snapshot.sessions[0].key;

        let mut replacement = process(10, Some(1), "codex", 1.0, 200);
        replacement.time = Duration::from_secs(1);
        state.refresh(
            &process_data(vec![replacement]),
            now + Duration::from_secs(1),
        );
        let replacement_key = state.snapshot.sessions[0].key;

        assert_ne!(first_key, replacement_key);
        assert_eq!(state.histories.len(), 2);
    }

    #[test]
    fn pid_reappearing_after_a_gap_does_not_inherit_history() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![process(10, Some(1), "codex", 1.0, 100)]),
            now,
        );
        let first_key = state.snapshot.sessions[0].key;

        state.refresh(&process_data(Vec::new()), now + Duration::from_secs(1));
        state.refresh(
            &process_data(vec![process(10, Some(1), "codex", 1.0, 200)]),
            now + Duration::from_secs(2),
        );
        let replacement_key = state.snapshot.sessions[0].key;

        assert_ne!(first_key, replacement_key);
        assert_eq!(state.histories.len(), 2);
    }

    #[test]
    fn pid_reused_while_collection_is_paused_does_not_inherit_history() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        let first = process(10, Some(1), "codex", 1.0, 100);
        state.refresh(&process_data(vec![first]), now);
        let first_key = state.snapshot.sessions[0].key;

        // No empty refresh occurs while collection is disabled. A replacement
        // process can therefore have the same PID and a larger uptime than the
        // last observed process without being the same process.
        let mut replacement = process(10, Some(1), "codex", 1.0, 200);
        replacement.time = Duration::from_secs(120);
        state.refresh(
            &process_data(vec![replacement]),
            now + Duration::from_secs(600),
        );
        let replacement_key = state.snapshot.sessions[0].key;

        assert_ne!(first_key, replacement_key);
        assert_eq!(state.histories.len(), 2);
    }

    #[test]
    fn same_process_after_collection_pause_keeps_history() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        let first = process(10, Some(1), "codex", 1.0, 100);
        state.refresh(&process_data(vec![first]), now);
        let first_key = state.snapshot.sessions[0].key;

        let mut continued = process(10, Some(1), "codex", 1.0, 200);
        continued.time = Duration::from_secs(660);
        state.refresh(
            &process_data(vec![continued]),
            now + Duration::from_secs(600),
        );

        assert_eq!(state.snapshot.sessions[0].key, first_key);
        assert_eq!(state.histories.len(), 1);
    }

    #[test]
    fn detached_finding_disappears_after_process_exits() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        let root = process(10, Some(1), "codex", 1.0, 10);
        let mut child = process(11, Some(10), "node", 1.0, 10);
        state.refresh(&process_data(vec![root, child.clone()]), now);

        child.parent_pid = Some(1);
        state.refresh(&process_data(vec![child]), now + Duration::from_secs(1));
        assert!(
            state
                .snapshot
                .findings
                .iter()
                .any(|finding| finding.kind == AgentFindingKind::Detached)
        );

        state.refresh(&process_data(Vec::new()), now + Duration::from_secs(2));
        assert!(state.snapshot.findings.is_empty());
    }

    #[test]
    fn selection_follows_session_identity_when_sort_order_changes() {
        let now = Instant::now();
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![
                process(10, Some(1), "codex", 1.0, 10),
                process(20, Some(1), "codex", 1.0, 10),
            ]),
            now,
        );
        state.selected_session = 1;
        let selected_key = state.selected().unwrap().key;

        state.refresh(
            &process_data(vec![
                process(5, Some(1), "codex", 1.0, 10),
                process(10, Some(1), "codex", 1.0, 10),
                process(20, Some(1), "codex", 1.0, 10),
            ]),
            now + Duration::from_secs(1),
        );

        assert_eq!(state.selected().unwrap().key, selected_key);
        assert_eq!(state.selected_session, 2);
    }
}
