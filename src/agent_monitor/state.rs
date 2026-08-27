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

use super::metadata::{CodexAnnotations, CodexMetadata};

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
pub(super) struct ThreadKey([u8; 16]);

impl ThreadKey {
    pub(super) fn parse(value: &str) -> Option<Self> {
        let hexadecimal = value
            .bytes()
            .filter(|byte| *byte != b'-')
            .collect::<Vec<_>>();
        if hexadecimal.len() != 32 {
            return None;
        }

        let mut bytes = [0_u8; 16];
        for (index, pair) in hexadecimal.chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            bytes[index] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }

    pub(super) fn short(self) -> String {
        self.to_string()[..8].to_string()
    }
}

impl fmt::Display for ThreadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum AgentSessionKind {
    CodexThread(ThreadKey),
    ProcessRoot,
    Runtime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct AgentSessionKey {
    pub(super) root: ProcessIdentity,
    kind: AgentSessionKind,
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
    pub(super) title: Option<String>,
    pub(super) cpu_usage_percent: f32,
    pub(super) rss_bytes: u64,
    pub(super) uptime: Duration,
    pub(super) processes: Vec<AgentProcess>,
    pub(super) zombie_count: usize,
}

impl AgentSession {
    pub(super) fn is_runtime(&self) -> bool {
        matches!(self.key.kind, AgentSessionKind::Runtime)
    }

    fn is_counted_session(&self) -> bool {
        !self.is_runtime()
    }

    pub(super) fn has_attributed_resources(&self) -> bool {
        !self.processes.is_empty()
    }

    fn thread_key(&self) -> Option<ThreadKey> {
        match self.key.kind {
            AgentSessionKind::CodexThread(thread) => Some(thread),
            AgentSessionKind::ProcessRoot | AgentSessionKind::Runtime => None,
        }
    }

    pub(super) fn display_title(&self) -> String {
        if let Some(title) = self.title.as_deref() {
            return title.to_string();
        }
        match self.key.kind {
            AgentSessionKind::CodexThread(thread) => format!("thread {}", thread.short()),
            AgentSessionKind::ProcessRoot => format!("#{}", self.key.root.pid),
            AgentSessionKind::Runtime => {
                format!("runtime #{} (unattributed)", self.key.root.pid)
            }
        }
    }

    pub(super) fn visible_processes(&self) -> impl Iterator<Item = &AgentProcess> {
        self.processes.iter().filter(|process| process.depth > 0)
    }
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
    pub(super) attributed_sessions: usize,
    pub(super) runtime_groups: usize,
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
    selected_process: Option<ProcessIdentity>,
    expanded_sessions: HashSet<AgentSessionKey>,
    pub(super) histories: HashMap<AgentSessionKey, AgentHistory>,
    pub(super) cpu_graph: AutoYAxisTimeGraph,
    pub(super) rss_graph: AutoYAxisTimeGraph,
    previous_owner: HashMap<ProcessIdentity, AgentSessionKey>,
    known_providers: HashMap<AgentSessionKey, AgentProvider>,
    observed_identities: HashMap<Pid, ObservedIdentity>,
    refresh_generation: u64,
    next_process_generation: u64,
    codex_metadata: CodexMetadata,
    live_metadata_enabled: bool,
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
            selected_process: None,
            expanded_sessions: HashSet::new(),
            histories: HashMap::new(),
            cpu_graph: AutoYAxisTimeGraph::new(graph_config, None),
            rss_graph: AutoYAxisTimeGraph::new(graph_config, None),
            previous_owner: HashMap::new(),
            known_providers: HashMap::new(),
            observed_identities: HashMap::new(),
            refresh_generation: 0,
            next_process_generation: 0,
            codex_metadata: CodexMetadata::new(),
            live_metadata_enabled: !cfg!(test),
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
        self.selected_process = None;
        self.expanded_sessions.clear();
        self.histories.clear();
        self.previous_owner.clear();
        self.known_providers.clear();
        self.observed_identities.clear();
        self.refresh_generation = 0;
        self.next_process_generation = 0;
        self.codex_metadata.clear();
        self.cpu_graph.state_mut().reset_zoom();
        self.rss_graph.state_mut().reset_zoom();
    }

    pub fn refresh(&mut self, process_data: &ProcessData, at: Instant) {
        let identities = self.refresh_process_identities(process_data, at);
        let roots = agent_roots(process_data);
        let annotations = if self.live_metadata_enabled {
            let codex_pids = roots
                .iter()
                .filter(|(_, provider)| *provider == AgentProvider::Codex)
                .flat_map(|(root_pid, _)| descendant_pids(*root_pid, process_data))
                .collect::<Vec<_>>();
            self.codex_metadata
                .refresh(&codex_pids, &identities, process_data, at)
        } else {
            CodexAnnotations::default()
        };

        self.refresh_with_annotations(process_data, at, identities, roots, annotations);
    }

    fn refresh_with_annotations(
        &mut self, process_data: &ProcessData, at: Instant,
        identities: HashMap<Pid, ProcessIdentity>, roots: Vec<(Pid, AgentProvider)>,
        annotations: CodexAnnotations,
    ) {
        let selected_key = self.selected().map(|session| session.key);
        let selected_process = self.selected_process;
        let codex_roots = roots
            .iter()
            .filter(|(_, provider)| *provider == AgentProvider::Codex)
            .filter_map(|(pid, _)| {
                let identity = identities.get(pid).copied()?;
                Some((identity, descendant_pids(*pid, process_data).len()))
            })
            .collect::<Vec<_>>();
        let mut current_owner = HashMap::new();
        let mut sessions = roots
            .into_iter()
            .flat_map(|(root_pid, provider)| {
                build_sessions(
                    root_pid,
                    provider,
                    process_data,
                    &identities,
                    &annotations,
                    &mut current_owner,
                )
            })
            .collect::<Vec<_>>();
        add_listed_codex_sessions(&mut sessions, &annotations, &codex_roots);
        sort_sessions(&mut sessions, &annotations);

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
                        "ZOMBIE pid {} ({}) under {}",
                        process.identity.pid,
                        process.name,
                        session.display_title()
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

        for session in sessions
            .iter()
            .filter(|session| session.has_attributed_resources())
        {
            let history = self.histories.entry(session.key).or_default();
            history.push(at, session);
            if let Some(growth) = history.rss_growth_bytes() {
                findings.push(AgentFinding {
                    kind: AgentFindingKind::RssRising,
                    message: format!(
                        "RSS rising +{} MiB for {} (not a leak verdict)",
                        growth / (1024 * 1024),
                        session.display_title()
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
            .filter(|session| {
                session.provider == AgentProvider::Codex && session.is_counted_session()
            })
            .count();
        let claude_sessions = sessions
            .iter()
            .filter(|session| {
                session.provider == AgentProvider::Claude && session.is_counted_session()
            })
            .count();
        let attributed_sessions = sessions
            .iter()
            .filter(|session| session.is_counted_session() && session.has_attributed_resources())
            .count();
        let runtime_groups = sessions
            .iter()
            .filter(|session| session.is_runtime())
            .count();

        self.snapshot = AgentSnapshot {
            sessions,
            findings,
            total_cpu_usage_percent,
            total_rss_bytes,
            total_processes,
            codex_sessions,
            claude_sessions,
            attributed_sessions,
            runtime_groups,
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
        self.expanded_sessions.retain(|key| {
            self.snapshot
                .sessions
                .iter()
                .any(|session| session.key == *key)
        });
        self.selected_process = selected_process.filter(|identity| {
            self.selected().is_some_and(|session| {
                self.expanded_sessions.contains(&session.key)
                    && session
                        .visible_processes()
                        .any(|process| process.identity == *identity)
            })
        });
    }

    #[cfg(test)]
    fn refresh_with_codex_threads_for_test(
        &mut self, process_data: &ProcessData, at: Instant, threads: &[(Pid, &str)],
        titles: &[(&str, &str)],
    ) {
        self.refresh_with_codex_annotations_for_test(process_data, at, threads, titles, &[]);
    }

    #[cfg(test)]
    fn refresh_with_codex_annotations_for_test(
        &mut self, process_data: &ProcessData, at: Instant, threads: &[(Pid, &str)],
        titles: &[(&str, &str)], listed_threads: &[&str],
    ) {
        let identities = self.refresh_process_identities(process_data, at);
        let roots = agent_roots(process_data);
        let annotations = CodexAnnotations {
            thread_by_pid: threads
                .iter()
                .filter_map(|(pid, thread)| ThreadKey::parse(thread).map(|thread| (*pid, thread)))
                .collect(),
            titles: titles
                .iter()
                .filter_map(|(thread, title)| {
                    ThreadKey::parse(thread).map(|thread| (thread, (*title).to_string()))
                })
                .collect(),
            listed_threads: listed_threads
                .iter()
                .filter_map(|thread| ThreadKey::parse(thread))
                .collect(),
        };
        self.refresh_with_annotations(process_data, at, identities, roots, annotations);
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

    pub(super) fn is_session_expanded(&self, key: AgentSessionKey) -> bool {
        self.expanded_sessions.contains(&key)
    }

    pub(super) fn is_process_selected(&self, identity: ProcessIdentity) -> bool {
        self.selected_process == Some(identity)
    }

    pub(super) fn is_session_selected(&self, index: usize) -> bool {
        self.selected_session == index && self.selected_process.is_none()
    }

    #[cfg(test)]
    fn is_selected_session_expanded(&self) -> bool {
        self.selected()
            .is_some_and(|session| self.is_session_expanded(session.key))
    }

    pub(crate) fn expand_selected_session(&mut self) {
        if self.selected_process.is_none()
            && let Some(key) = self.selected().map(|session| session.key)
        {
            self.expanded_sessions.insert(key);
        }
    }

    pub(crate) fn collapse_selected_session(&mut self) {
        if self.selected_process.take().is_some() {
            return;
        }
        if let Some(key) = self.selected().map(|session| session.key) {
            self.expanded_sessions.remove(&key);
        }
    }

    fn visible_selection(&self) -> Vec<(usize, Option<ProcessIdentity>)> {
        let mut rows = Vec::new();
        for (session_index, session) in self.snapshot.sessions.iter().enumerate() {
            rows.push((session_index, None));
            if self.is_session_expanded(session.key) {
                rows.extend(
                    session
                        .visible_processes()
                        .map(|process| (session_index, Some(process.identity))),
                );
            }
        }
        rows
    }

    #[cfg(test)]
    fn selected_process_pid(&self) -> Option<Pid> {
        self.selected_process.map(|identity| identity.pid)
    }

    pub fn increment_selection(&mut self, amount: i64) {
        let rows = self.visible_selection();
        if rows.is_empty() {
            self.selected_session = 0;
            self.selected_process = None;
            return;
        }
        let current = rows
            .iter()
            .position(|(session, process)| {
                *session == self.selected_session && *process == self.selected_process
            })
            .unwrap_or(0);
        let next = if amount.is_negative() {
            current.saturating_sub(amount.unsigned_abs() as usize)
        } else {
            current.saturating_add(amount as usize).min(rows.len() - 1)
        };
        (self.selected_session, self.selected_process) = rows[next];
    }

    pub fn select_first(&mut self) {
        self.selected_session = 0;
        self.selected_process = None;
    }

    pub fn select_last(&mut self) {
        self.selected_session = self.snapshot.sessions.len().saturating_sub(1);
        self.selected_process = None;
    }
}

fn instant_distance(left: Instant, right: Instant) -> Duration {
    if left >= right {
        left.duration_since(right)
    } else {
        right.duration_since(left)
    }
}

fn agent_roots(process_data: &ProcessData) -> Vec<(Pid, AgentProvider)> {
    let provider_by_pid = process_data
        .process_harvest
        .values()
        .filter_map(|process| detect_provider(process).map(|provider| (process.pid, provider)))
        .collect::<HashMap<_, _>>();
    let mut roots = provider_by_pid
        .iter()
        .filter_map(|(&pid, &provider)| {
            (!has_agent_ancestor(pid, process_data, &provider_by_pid)).then_some((pid, provider))
        })
        .collect::<Vec<_>>();
    roots.sort_unstable_by_key(|(pid, provider)| (*provider, *pid));
    roots
}

fn descendant_pids(root_pid: Pid, process_data: &ProcessData) -> Vec<Pid> {
    let mut pids = Vec::new();
    let mut stack = vec![root_pid];
    let mut visited = HashSet::new();
    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) || !process_data.process_harvest.contains_key(&pid) {
            continue;
        }
        pids.push(pid);
        if let Some(children) = process_data.process_parent_mapping.get(&pid) {
            stack.extend(children.iter().copied());
        }
    }
    pids
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

fn add_listed_codex_sessions(
    sessions: &mut Vec<AgentSession>, annotations: &CodexAnnotations,
    codex_roots: &[(ProcessIdentity, usize)],
) {
    if annotations.listed_threads.is_empty() {
        return;
    }

    let existing_threads = sessions
        .iter()
        .filter_map(AgentSession::thread_key)
        .collect::<HashSet<_>>();
    let mut observed_by_root = HashMap::<ProcessIdentity, usize>::new();
    for session in sessions
        .iter()
        .filter(|session| session.provider == AgentProvider::Codex)
        .filter(|session| session.thread_key().is_some())
    {
        *observed_by_root.entry(session.key.root).or_default() += 1;
    }
    let preferred_root = observed_by_root
        .into_iter()
        .max_by_key(|(root, count)| (*count, root.pid))
        .map(|(root, _)| root)
        .or_else(|| {
            codex_roots
                .iter()
                .max_by_key(|(root, process_count)| (*process_count, root.pid))
                .map(|(root, _)| *root)
        });
    let Some(root) = preferred_root else {
        return;
    };

    for thread in annotations
        .listed_threads
        .iter()
        .copied()
        .filter(|thread| !existing_threads.contains(thread))
    {
        sessions.push(AgentSession {
            key: AgentSessionKey {
                root,
                kind: AgentSessionKind::CodexThread(thread),
            },
            provider: AgentProvider::Codex,
            title: annotations.titles.get(&thread).cloned(),
            cpu_usage_percent: 0.0,
            rss_bytes: 0,
            uptime: Duration::ZERO,
            processes: Vec::new(),
            zombie_count: 0,
        });
    }
}

fn sort_sessions(sessions: &mut [AgentSession], annotations: &CodexAnnotations) {
    let listed_order = annotations
        .listed_threads
        .iter()
        .enumerate()
        .map(|(index, thread)| (*thread, index))
        .collect::<HashMap<_, _>>();
    sessions.sort_unstable_by_key(|session| {
        let group = match (session.provider, session.key.kind) {
            (AgentProvider::Codex, AgentSessionKind::CodexThread(_)) => 0,
            (AgentProvider::Codex, AgentSessionKind::ProcessRoot) => 1,
            (AgentProvider::Codex, AgentSessionKind::Runtime) => 2,
            (AgentProvider::Claude, _) => 3,
        };
        let listed_index = session
            .thread_key()
            .and_then(|thread| listed_order.get(&thread).copied())
            .unwrap_or(usize::MAX);
        (group, listed_index, session.key.root.pid, session.key.kind)
    });
}

fn build_sessions(
    root_pid: Pid, provider: AgentProvider, process_data: &ProcessData,
    identities: &HashMap<Pid, ProcessIdentity>, annotations: &CodexAnnotations,
    owner: &mut HashMap<ProcessIdentity, AgentSessionKey>,
) -> Vec<AgentSession> {
    let Some(root_identity) = identities.get(&root_pid).copied() else {
        return Vec::new();
    };

    let mut ordered_processes = Vec::new();
    let mut stack = vec![(root_pid, 0_usize)];
    let mut visited = HashSet::new();
    while let Some((pid, depth)) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if !process_data.process_harvest.contains_key(&pid) || !identities.contains_key(&pid) {
            continue;
        }
        ordered_processes.push((pid, depth));

        if let Some(children) = process_data.process_parent_mapping.get(&pid) {
            let mut children = children.clone();
            children.sort_unstable();
            stack.extend(children.into_iter().rev().map(|child| (child, depth + 1)));
        }
    }

    let mut evidence_by_pid = HashMap::new();
    for (pid, _) in ordered_processes.iter().rev() {
        let mut evidence = annotations
            .thread_by_pid
            .get(pid)
            .copied()
            .map(ThreadEvidence::One)
            .unwrap_or(ThreadEvidence::None);
        if let Some(children) = process_data.process_parent_mapping.get(pid) {
            for child in children {
                evidence = evidence.merge(
                    evidence_by_pid
                        .get(child)
                        .copied()
                        .unwrap_or(ThreadEvidence::None),
                );
            }
        }
        evidence_by_pid.insert(*pid, evidence);
    }

    let mut tagged_processes = Vec::with_capacity(ordered_processes.len());
    let mut inherited_by_pid = HashMap::<Pid, ThreadKey>::new();
    for (pid, depth) in ordered_processes {
        let direct_thread = annotations.thread_by_pid.get(&pid).copied();
        let inherited_thread = process_data
            .process_harvest
            .get(&pid)
            .and_then(|process| process.parent_pid)
            .and_then(|parent| inherited_by_pid.get(&parent).copied());
        let inferred_thread = (pid != root_pid)
            .then(|| evidence_by_pid.get(&pid).copied())
            .flatten()
            .and_then(ThreadEvidence::single);
        let thread = direct_thread.or(inherited_thread).or(inferred_thread);
        if let Some(thread) = thread {
            inherited_by_pid.insert(pid, thread);
        }

        let Some(process) = process_data.process_harvest.get(&pid) else {
            continue;
        };
        let Some(identity) = identities.get(&pid).copied() else {
            continue;
        };
        tagged_processes.push((thread, AgentProcess::from_harvest(process, identity, depth)));
    }

    if provider != AgentProvider::Codex
        || !tagged_processes.iter().any(|(thread, _)| thread.is_some())
    {
        let kind = if provider == AgentProvider::Codex
            && process_data
                .process_harvest
                .get(&root_pid)
                .is_some_and(|process| {
                    process
                        .command
                        .split_whitespace()
                        .any(|argument| argument == "app-server")
                }) {
            AgentSessionKind::Runtime
        } else {
            AgentSessionKind::ProcessRoot
        };
        let processes = tagged_processes
            .into_iter()
            .map(|(_, process)| process)
            .collect();
        let sessions = session_from_processes(
            AgentSessionKey {
                root: root_identity,
                kind,
            },
            provider,
            None,
            processes,
            process_data,
            owner,
        )
        .into_iter()
        .collect::<Vec<_>>();
        debug_assert_resource_conservation(&sessions, process_data, root_pid);
        return sessions;
    }

    let mut grouped = HashMap::<Option<ThreadKey>, Vec<AgentProcess>>::new();
    for (thread, process) in tagged_processes {
        grouped.entry(thread).or_default().push(process);
    }

    let sessions = grouped
        .into_iter()
        .filter_map(|(thread, processes)| {
            let (kind, title) = if let Some(thread) = thread {
                (
                    AgentSessionKind::CodexThread(thread),
                    annotations.titles.get(&thread).cloned(),
                )
            } else {
                (AgentSessionKind::Runtime, None)
            };
            session_from_processes(
                AgentSessionKey {
                    root: root_identity,
                    kind,
                },
                provider,
                title,
                processes,
                process_data,
                owner,
            )
        })
        .collect::<Vec<_>>();
    debug_assert_resource_conservation(&sessions, process_data, root_pid);
    sessions
}

#[derive(Clone, Copy)]
enum ThreadEvidence {
    None,
    One(ThreadKey),
    Multiple,
}

impl ThreadEvidence {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Multiple, _) | (_, Self::Multiple) => Self::Multiple,
            (Self::None, evidence) | (evidence, Self::None) => evidence,
            (Self::One(left), Self::One(right)) if left == right => Self::One(left),
            (Self::One(_), Self::One(_)) => Self::Multiple,
        }
    }

    fn single(self) -> Option<ThreadKey> {
        match self {
            Self::One(thread) => Some(thread),
            Self::None | Self::Multiple => None,
        }
    }
}

fn debug_assert_resource_conservation(
    sessions: &[AgentSession], process_data: &ProcessData, root_pid: Pid,
) {
    #[cfg(not(debug_assertions))]
    let _ = (sessions, process_data, root_pid);

    #[cfg(debug_assertions)]
    {
        let root_pids = descendant_pids(root_pid, process_data);
        let expected_processes = root_pids.len();
        let expected_rss = root_pids
            .iter()
            .filter_map(|pid| process_data.process_harvest.get(pid))
            .map(|process| process.mem_usage)
            .sum::<u64>();
        let expected_cpu = root_pids
            .iter()
            .filter_map(|pid| process_data.process_harvest.get(pid))
            .map(|process| process.cpu_usage_percent)
            .sum::<f32>();
        let actual_processes = sessions
            .iter()
            .map(|session| session.processes.len())
            .sum::<usize>();
        let actual_rss = sessions
            .iter()
            .map(|session| session.rss_bytes)
            .sum::<u64>();
        let actual_cpu = sessions
            .iter()
            .map(|session| session.cpu_usage_percent)
            .sum::<f32>();
        let cpu_tolerance = expected_cpu.abs().max(1.0) * f32::EPSILON * 8.0;

        debug_assert_eq!(actual_processes, expected_processes);
        debug_assert_eq!(actual_rss, expected_rss);
        debug_assert!((actual_cpu - expected_cpu).abs() <= cpu_tolerance);
    }
}

fn session_from_processes(
    key: AgentSessionKey, provider: AgentProvider, title: Option<String>,
    processes: Vec<AgentProcess>, process_data: &ProcessData,
    owner: &mut HashMap<ProcessIdentity, AgentSessionKey>,
) -> Option<AgentSession> {
    if processes.is_empty() {
        return None;
    }
    for process in &processes {
        owner.insert(process.identity, key);
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
    let uptime = processes
        .iter()
        .filter_map(|process| process_data.process_harvest.get(&process.identity.pid))
        .map(|process| process.time)
        .max()
        .unwrap_or_default();

    Some(AgentSession {
        key,
        provider,
        title,
        cpu_usage_percent,
        rss_bytes,
        uptime,
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
    fn codex_processes_are_split_by_thread_and_runtime_resources_stay_separate() {
        let data = process_data(vec![
            process(10, Some(1), "codex", 10.0, 100),
            process(11, Some(10), "node", 5.0, 200),
            process(12, Some(11), "cargo", 2.0, 300),
            process(13, Some(10), "node", 3.0, 400),
        ]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh_with_codex_threads_for_test(
            &data,
            Instant::now(),
            &[
                (11, "01a041af-04ff-7f31-858e-67724bfa8e56"),
                (13, "01a041c1-1c25-7400-94cc-5efd2517517d"),
            ],
            &[
                (
                    "01a041af-04ff-7f31-858e-67724bfa8e56",
                    "Knowledge quality skill",
                ),
                (
                    "01a041c1-1c25-7400-94cc-5efd2517517d",
                    "Agent Monitor sessions",
                ),
            ],
        );

        assert_eq!(state.snapshot.codex_sessions, 2);
        assert_eq!(state.snapshot.runtime_groups, 1);
        assert_eq!(state.snapshot.sessions.len(), 3);

        let first = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.title.as_deref() == Some("Knowledge quality skill"))
            .unwrap();
        assert_eq!(first.cpu_usage_percent, 7.0);
        assert_eq!(first.rss_bytes, 500);
        assert_eq!(
            first
                .processes
                .iter()
                .map(|process| process.identity.pid)
                .collect::<Vec<_>>(),
            vec![11, 12]
        );

        let second = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.title.as_deref() == Some("Agent Monitor sessions"))
            .unwrap();
        assert_eq!(second.cpu_usage_percent, 3.0);
        assert_eq!(second.rss_bytes, 400);
        assert_eq!(second.processes.len(), 1);

        let runtime = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.is_runtime())
            .unwrap();
        assert_eq!(runtime.cpu_usage_percent, 10.0);
        assert_eq!(runtime.rss_bytes, 100);
        assert_eq!(runtime.processes.len(), 1);
    }

    #[test]
    fn listed_codex_thread_without_a_process_is_visible_but_not_reported_as_zero_usage() {
        let observed = "01a041c1-1c25-7400-94cc-5efd2517517d";
        let listed_only = "01a041e1-5e15-78e1-b323-641ec611a480";
        let data = process_data(vec![
            process(10, Some(1), "codex", 10.0, 100),
            process(11, Some(10), "zsh", 5.0, 200),
        ]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh_with_codex_annotations_for_test(
            &data,
            Instant::now(),
            &[(11, observed)],
            &[(observed, "Observed"), (listed_only, "Listed only")],
            &[observed, listed_only],
        );

        assert_eq!(state.snapshot.codex_sessions, 2);
        assert_eq!(state.snapshot.attributed_sessions, 1);
        let listed = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.title.as_deref() == Some("Listed only"))
            .unwrap();
        assert!(!listed.has_attributed_resources());
        assert!(listed.processes.is_empty());

        // A display-only session must not change the conserved resource total.
        assert_eq!(state.snapshot.total_cpu_usage_percent, 15.0);
        assert_eq!(state.snapshot.total_rss_bytes, 300);
        assert_eq!(state.snapshot.total_processes, 2);
    }

    #[test]
    fn descendant_thread_identity_claims_its_wrapper_branch_and_conserves_root_totals() {
        let data = process_data(vec![
            process(10, Some(1), "codex", 10.0, 100),
            process(11, Some(10), "node_repl", 5.0, 200),
            process(12, Some(11), "codex sandbox", 2.0, 300),
            process(13, Some(11), "codex app-server", 3.0, 400),
            process(14, Some(10), "mcp", 4.0, 500),
        ]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh_with_codex_threads_for_test(
            &data,
            Instant::now(),
            &[(12, "01a041f5-34ac-7770-96d1-c0948d6cd574")],
            &[(
                "01a041f5-34ac-7770-96d1-c0948d6cd574",
                "Code blocks by line",
            )],
        );

        let thread = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.title.as_deref() == Some("Code blocks by line"))
            .unwrap();
        assert_eq!(
            thread
                .processes
                .iter()
                .map(|process| process.identity.pid)
                .collect::<Vec<_>>(),
            vec![11, 12, 13]
        );
        assert_eq!(thread.cpu_usage_percent, 10.0);
        assert_eq!(thread.rss_bytes, 900);

        let runtime = state
            .snapshot
            .sessions
            .iter()
            .find(|session| session.is_runtime())
            .unwrap();
        assert_eq!(
            runtime
                .processes
                .iter()
                .map(|process| process.identity.pid)
                .collect::<Vec<_>>(),
            vec![10, 14]
        );

        assert_eq!(
            state
                .snapshot
                .sessions
                .iter()
                .map(|session| session.cpu_usage_percent)
                .sum::<f32>(),
            24.0
        );
        assert_eq!(state.snapshot.total_rss_bytes, 1_500);
        assert_eq!(state.snapshot.total_processes, 5);
    }

    #[test]
    fn codex_app_server_without_thread_metadata_is_unattributed_runtime_resource() {
        let mut root = process(10, Some(1), "node", 10.0, 100);
        root.command = "node /opt/codex app-server --listen stdio://".to_string();
        let data = process_data(vec![root, process(11, Some(10), "node", 5.0, 200)]);
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(&data, Instant::now());

        assert_eq!(state.snapshot.codex_sessions, 0);
        assert_eq!(state.snapshot.runtime_groups, 1);
        assert!(state.snapshot.sessions[0].is_runtime());
        assert_eq!(state.snapshot.sessions[0].rss_bytes, 300);
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

    #[test]
    fn process_trees_start_collapsed_and_expand_on_request() {
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![
                process(10, Some(1), "codex", 1.0, 10),
                process(11, Some(10), "node", 1.0, 10),
            ]),
            Instant::now(),
        );

        assert!(!state.is_selected_session_expanded());
        state.expand_selected_session();
        assert!(state.is_selected_session_expanded());
    }

    #[test]
    fn expanded_process_rows_are_reachable_with_tree_navigation() {
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![
                process(10, Some(1), "codex", 1.0, 10),
                process(11, Some(10), "node", 1.0, 10),
                process(12, Some(11), "cargo", 1.0, 10),
                process(20, Some(1), "claude", 1.0, 10),
            ]),
            Instant::now(),
        );

        state.expand_selected_session();
        state.increment_selection(2);

        assert_eq!(state.selected_session, 0);
        assert_eq!(state.selected_process_pid(), Some(12));

        state.increment_selection(1);
        assert_eq!(state.selected_session, 1);
        assert_eq!(state.selected_process_pid(), None);
    }

    #[test]
    fn left_from_a_process_returns_to_its_session_then_collapses_it() {
        let mut state = AgentMonitor::new(&config(), false, false);
        state.refresh(
            &process_data(vec![
                process(10, Some(1), "codex", 1.0, 10),
                process(11, Some(10), "node", 1.0, 10),
            ]),
            Instant::now(),
        );

        state.expand_selected_session();
        state.increment_selection(1);
        assert_eq!(state.selected_process_pid(), Some(11));

        state.collapse_selected_session();
        assert_eq!(state.selected_process_pid(), None);
        assert!(state.is_selected_session_expanded());

        state.collapse_selected_session();
        assert!(!state.is_selected_session_expanded());
    }
}
