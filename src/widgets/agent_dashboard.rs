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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentProvider {
    Codex,
    Claude,
}

impl AgentProvider {
    pub const fn label(self) -> &'static str {
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
pub struct ProcessIdentity {
    pub pid: Pid,
    pub start_time: u64,
}

impl From<&ProcessHarvest> for ProcessIdentity {
    fn from(process: &ProcessHarvest) -> Self {
        Self {
            pid: process.pid,
            start_time: process.start_time,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentSessionKey {
    pub root: ProcessIdentity,
}

#[derive(Clone, Debug)]
pub struct AgentProcess {
    pub identity: ProcessIdentity,
    pub parent_pid: Option<Pid>,
    pub name: String,
    pub depth: usize,
    pub cpu_usage_percent: f32,
    pub rss_bytes: u64,
    pub state: &'static str,
    pub state_char: char,
}

impl AgentProcess {
    fn from_harvest(process: &ProcessHarvest, depth: usize) -> Self {
        Self {
            identity: process.into(),
            parent_pid: process.parent_pid,
            name: process.name.clone(),
            depth,
            cpu_usage_percent: process.cpu_usage_percent,
            rss_bytes: process.mem_usage,
            state: process.process_state.0,
            state_char: process.process_state.1,
        }
    }

    pub fn is_zombie(&self) -> bool {
        self.state.eq_ignore_ascii_case("zombie") || self.state_char == 'Z'
    }
}

#[derive(Clone, Debug)]
pub struct AgentSession {
    pub key: AgentSessionKey,
    pub provider: AgentProvider,
    pub root_name: String,
    pub cpu_usage_percent: f32,
    pub rss_bytes: u64,
    pub uptime: Duration,
    pub processes: Vec<AgentProcess>,
    pub zombie_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentFindingKind {
    Zombie,
    Detached,
    RssRising,
}

#[derive(Clone, Debug)]
pub struct AgentFinding {
    pub kind: AgentFindingKind,
    pub provider: AgentProvider,
    pub pid: Pid,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct AgentSnapshot {
    pub sessions: Vec<AgentSession>,
    pub findings: Vec<AgentFinding>,
    pub total_cpu_usage_percent: f32,
    pub total_rss_bytes: u64,
    pub total_processes: usize,
    pub codex_sessions: usize,
    pub claude_sessions: usize,
}

#[derive(Clone, Debug, Default)]
pub struct AgentHistory {
    pub time: Vec<Instant>,
    pub cpu: ChunkedData<f64>,
    pub rss_mib: ChunkedData<f64>,
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

pub struct AgentWidgetState {
    pub snapshot: AgentSnapshot,
    pub selected_session: usize,
    pub histories: HashMap<AgentSessionKey, AgentHistory>,
    pub cpu_graph: AutoYAxisTimeGraph,
    pub rss_graph: AutoYAxisTimeGraph,
    previous_owner: HashMap<ProcessIdentity, AgentSessionKey>,
    known_providers: HashMap<AgentSessionKey, AgentProvider>,
}

impl AgentWidgetState {
    pub fn new(config: &AppConfigFields) -> Self {
        let graph_config = TimeseriesConfig {
            time_interval: config.time_interval,
            retention_ms: config.retention_ms,
            autohide_time: config.autohide_time,
            default_time_value: config.default_time_value,
        };

        Self {
            snapshot: AgentSnapshot::default(),
            selected_session: 0,
            histories: HashMap::new(),
            cpu_graph: AutoYAxisTimeGraph::new(graph_config, None),
            rss_graph: AutoYAxisTimeGraph::new(graph_config, None),
            previous_owner: HashMap::new(),
            known_providers: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.snapshot = AgentSnapshot::default();
        self.selected_session = 0;
        self.histories.clear();
        self.previous_owner.clear();
        self.known_providers.clear();
        self.cpu_graph.state_mut().reset_zoom();
        self.rss_graph.state_mut().reset_zoom();
    }

    pub fn refresh(&mut self, process_data: &ProcessData, at: Instant) {
        let selected_key = self.selected().map(|session| session.key);
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
                build_session(root_pid, provider, process_data, &mut current_owner)
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
                    provider: session.provider,
                    pid: process.identity.pid,
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
            let identity = ProcessIdentity::from(process);
            if current_owner.contains_key(&identity) {
                continue;
            }

            if let Some(previous_session) = self.previous_owner.get(&identity).copied()
                && let Some(provider) = self.known_providers.get(&previous_session).copied()
            {
                current_owner.insert(identity, previous_session);
                findings.push(AgentFinding {
                    kind: AgentFindingKind::Detached,
                    provider,
                    pid: process.pid,
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
                    provider: session.provider,
                    pid: session.key.root.pid,
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

    pub fn selected(&self) -> Option<&AgentSession> {
        self.snapshot.sessions.get(self.selected_session)
    }

    pub fn selected_history(&self) -> Option<&AgentHistory> {
        let session = self.selected()?;
        self.histories.get(&session.key)
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
    owner: &mut HashMap<ProcessIdentity, AgentSessionKey>,
) -> Option<AgentSession> {
    let root = process_data.process_harvest.get(&root_pid)?;
    let key = AgentSessionKey {
        root: ProcessIdentity::from(root),
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

        let identity = ProcessIdentity::from(process);
        owner.insert(identity, key);
        processes.push(AgentProcess::from_harvest(process, depth));

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
        root_name: root.name.clone(),
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
            start_time: pid as u64 * 10,
            ..ProcessHarvest::default()
        }
    }

    fn process_data(processes: Vec<ProcessHarvest>) -> ProcessData {
        let mut data = ProcessData::default();
        data.ingest(processes);
        data
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
        let mut state = AgentWidgetState::new(&config());
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
        let mut state = AgentWidgetState::new(&config());
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

        let mut state = AgentWidgetState::new(&config());
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
        let mut state = AgentWidgetState::new(&config());
        state.refresh(
            &process_data(vec![process(10, Some(1), "codex", 1.0, 100 * 1024 * 1024)]),
            now,
        );
        state.refresh(
            &process_data(vec![process(10, Some(1), "codex", 1.0, 180 * 1024 * 1024)]),
            now + Duration::from_secs(61),
        );

        assert!(state.snapshot.findings.iter().any(|finding| {
            finding.kind == AgentFindingKind::RssRising
                && finding.message.contains("not a leak verdict")
        }));
    }
}
