//! Codex-owned process and thread metadata discovery.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, params};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::{app::data::ProcessData, collection::processes::Pid};

use super::state::{ProcessIdentity, ThreadKey};

const TITLE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct CodexAnnotations {
    pub(super) thread_by_pid: HashMap<Pid, ThreadKey>,
    pub(super) titles: HashMap<ThreadKey, String>,
    pub(super) listed_threads: Vec<ThreadKey>,
}

struct ListedThread {
    key: ThreadKey,
    title: String,
}

pub(super) struct CodexMetadata {
    thread_by_identity: HashMap<ProcessIdentity, Option<ThreadKey>>,
    titles: HashMap<ThreadKey, String>,
    listed_threads: Vec<ThreadKey>,
    state_db: Option<PathBuf>,
    session_index: Option<PathBuf>,
    last_title_refresh: Option<Instant>,
}

impl CodexMetadata {
    pub(super) fn new() -> Self {
        let codex_home = codex_home();
        Self {
            thread_by_identity: HashMap::new(),
            titles: HashMap::new(),
            listed_threads: Vec::new(),
            state_db: codex_home.as_deref().and_then(newest_state_db),
            session_index: codex_home.map(|home| home.join("session_index.jsonl")),
            last_title_refresh: None,
        }
    }

    pub(super) fn clear(&mut self) {
        self.thread_by_identity.clear();
        self.titles.clear();
        self.listed_threads.clear();
        self.last_title_refresh = None;
    }

    pub(super) fn refresh(
        &mut self, candidate_pids: &[Pid], identities: &HashMap<Pid, ProcessIdentity>,
        process_data: &ProcessData, at: Instant,
    ) -> CodexAnnotations {
        let current_identities = identities.values().copied().collect::<HashSet<_>>();
        self.thread_by_identity
            .retain(|identity, _| current_identities.contains(identity));

        let unseen = candidate_pids
            .iter()
            .filter_map(|pid| {
                let identity = *identities.get(pid)?;
                (!self.thread_by_identity.contains_key(&identity)).then_some((*pid, identity))
            })
            .collect::<Vec<_>>();
        let sysinfo_pids = unseen
            .iter()
            .map(|(pid, _)| sysinfo::Pid::from_u32(*pid as u32))
            .collect::<Vec<_>>();

        if !sysinfo_pids.is_empty() {
            let mut system = System::new();
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&sysinfo_pids),
                true,
                ProcessRefreshKind::nothing()
                    .with_environ(UpdateKind::Always)
                    .without_tasks(),
            );
            for (pid, identity) in unseen {
                let environment_thread = system
                    .process(sysinfo::Pid::from_u32(pid as u32))
                    .and_then(|process| thread_key_from_environment(process.environ()));
                let command_thread = process_data
                    .process_harvest
                    .get(&pid)
                    .and_then(|process| thread_key_from_command(&process.command));
                let thread = environment_thread.or(command_thread);
                self.thread_by_identity.insert(identity, thread);
            }
        }

        let thread_by_pid = candidate_pids
            .iter()
            .filter_map(|pid| {
                let identity = identities.get(pid)?;
                self.thread_by_identity
                    .get(identity)
                    .copied()
                    .flatten()
                    .map(|thread| (*pid, thread))
            })
            .collect::<HashMap<_, _>>();
        let live_threads = thread_by_pid.values().copied().collect::<HashSet<_>>();
        let titles_stale = self
            .last_title_refresh
            .is_none_or(|last| at.duration_since(last) >= TITLE_REFRESH_INTERVAL);
        if titles_stale
            || live_threads
                .iter()
                .any(|thread| !self.titles.contains_key(thread))
        {
            self.refresh_state(&live_threads);
            self.last_title_refresh = Some(at);
        }

        let displayed_threads = live_threads
            .iter()
            .copied()
            .chain(self.listed_threads.iter().copied())
            .collect::<HashSet<_>>();

        CodexAnnotations {
            thread_by_pid,
            titles: displayed_threads
                .into_iter()
                .filter_map(|thread| {
                    self.titles
                        .get(&thread)
                        .cloned()
                        .map(|title| (thread, title))
                })
                .collect(),
            listed_threads: self.listed_threads.clone(),
        }
    }

    fn refresh_state(&mut self, threads: &HashSet<ThreadKey>) {
        if let Some(path) = self.state_db.as_deref()
            && let Ok(connection) = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
        {
            let listed_threads = read_pinned_threads(&connection);
            self.listed_threads = listed_threads.iter().map(|thread| thread.key).collect();
            for thread in listed_threads {
                self.titles.insert(thread.key, thread.title);
            }

            for thread in threads {
                if let Some(title) = read_thread_title(&connection, *thread) {
                    self.titles.insert(*thread, title);
                }
            }
        }

        if let Some(path) = self.session_index.as_deref()
            && let Ok(file) = File::open(path)
        {
            for (thread, title) in read_session_index_titles(BufReader::new(file)) {
                self.titles.insert(thread, title);
            }
        }
    }
}

fn thread_key_from_environment(environment: &[std::ffi::OsString]) -> Option<ThreadKey> {
    environment.iter().find_map(|entry| {
        entry
            .to_str()
            .and_then(|entry| entry.strip_prefix("CODEX_THREAD_ID="))
            .and_then(ThreadKey::parse)
    })
}

fn thread_key_from_command(command: &str) -> Option<ThreadKey> {
    ["/.codex/visualizations/", "\\.codex\\visualizations\\"]
        .into_iter()
        .filter_map(|marker| command.split_once(marker).map(|(_, suffix)| suffix))
        .find_map(|suffix| {
            suffix
                .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
                .find_map(ThreadKey::parse)
        })
}

fn read_thread_title(connection: &Connection, thread: ThreadKey) -> Option<String> {
    let id = thread.to_string();
    let preferred = connection.query_row(
        "SELECT name, title FROM threads WHERE id = ?1",
        params![id],
        |row| {
            let name = row.get::<_, Option<String>>(0)?;
            let title = row.get::<_, String>(1)?;
            Ok(name.filter(|name| !name.trim().is_empty()).unwrap_or(title))
        },
    );

    preferred.ok().and_then(|title| first_title_line(&title))
}

fn read_pinned_threads(connection: &Connection) -> Vec<ListedThread> {
    let Ok(mut statement) = connection.prepare(
        "SELECT t.id, t.name, t.title
         FROM threads t
         JOIN thread_sections s ON s.id = t.thread_section_id
         WHERE s.name = 'Pinned' AND t.archived = 0
         ORDER BY t.section_position IS NULL, t.section_position, t.id",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = statement.query_map([], |row| {
        let id = row.get::<_, String>(0)?;
        let name = row.get::<_, Option<String>>(1)?;
        let title = row.get::<_, String>(2)?;
        Ok((id, name, title))
    }) else {
        return Vec::new();
    };

    rows.filter_map(Result::ok)
        .filter_map(|(id, name, title)| {
            let key = ThreadKey::parse(&id)?;
            let preferred = name.filter(|name| !name.trim().is_empty()).unwrap_or(title);
            let title = first_title_line(&preferred)?;
            Some(ListedThread { key, title })
        })
        .collect()
}

#[derive(serde::Deserialize)]
struct SessionIndexEntry {
    id: String,
    thread_name: String,
}

fn read_session_index_titles(reader: impl BufRead) -> HashMap<ThreadKey, String> {
    reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<SessionIndexEntry>(&line).ok())
        .filter_map(|entry| {
            let thread = ThreadKey::parse(&entry.id)?;
            let title = first_title_line(&entry.thread_name)?;
            Some((thread, title))
        })
        .collect()
}

fn first_title_line(title: &str) -> Option<String> {
    title
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn codex_home() -> Option<PathBuf> {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".codex")))
}

fn newest_state_db(codex_home: &Path) -> Option<PathBuf> {
    std::fs::read_dir(codex_home)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let version = state_db_version(path.file_name()?)?;
            Some((version, path))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, path)| path)
}

fn state_db_version(file_name: &OsStr) -> Option<u32> {
    let name = file_name.to_str()?;
    name.strip_prefix("state_")?
        .strip_suffix(".sqlite")?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_codex_thread_id_without_reading_other_environment_values() {
        let environment = vec![
            "TOKEN=secret".into(),
            "CODEX_THREAD_ID=01a041c1-1c25-7400-94cc-5efd2517517d".into(),
        ];

        assert_eq!(
            thread_key_from_environment(&environment),
            ThreadKey::parse("01a041c1-1c25-7400-94cc-5efd2517517d")
        );
    }

    #[test]
    fn parses_thread_id_from_codex_visualization_path() {
        let command = concat!(
            "codex sandbox -c permissions.node_repl={filesystem={\"",
            "/Users/test/.codex/visualizations/2026/08/27/",
            "01a041f5-34ac-7770-96d1-c0948d6cd574\"=\"write\"}}",
        );

        assert_eq!(
            thread_key_from_command(command),
            ThreadKey::parse("01a041f5-34ac-7770-96d1-c0948d6cd574")
        );
        assert_eq!(
            thread_key_from_command(
                "zsh -c discuss 01a041f5-34ac-7770-96d1-c0948d6cd574 in a prompt"
            ),
            None
        );
    }

    #[test]
    fn recognizes_only_versioned_codex_state_databases() {
        assert_eq!(state_db_version(OsStr::new("state_5.sqlite")), Some(5));
        assert_eq!(state_db_version(OsStr::new("state.sqlite")), None);
        assert_eq!(state_db_version(OsStr::new("state_5.sqlite-wal")), None);
    }

    #[test]
    fn reads_the_user_visible_thread_name_before_the_first_message() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT, title TEXT NOT NULL)",
                [],
            )
            .unwrap();
        let thread = ThreadKey::parse("01a041c1-1c25-7400-94cc-5efd2517517d").unwrap();
        connection
            .execute(
                "INSERT INTO threads (id, name, title) VALUES (?1, ?2, ?3)",
                params![
                    thread.to_string(),
                    "Agent Monitor sessions",
                    "Long first message"
                ],
            )
            .unwrap();

        assert_eq!(
            read_thread_title(&connection, thread).as_deref(),
            Some("Agent Monitor sessions")
        );
    }

    #[test]
    fn reads_pinned_codex_threads_in_sidebar_order() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE thread_sections (id TEXT PRIMARY KEY, name TEXT NOT NULL);\
                 CREATE TABLE threads (\
                    id TEXT PRIMARY KEY, name TEXT, title TEXT NOT NULL, archived INTEGER NOT NULL,\
                    thread_section_id TEXT, section_position INTEGER\
                 );\
                 INSERT INTO thread_sections (id, name) VALUES ('pinned', 'Pinned');\
                 INSERT INTO threads VALUES\
                    ('01a041f5-34ac-7770-96d1-c0948d6cd574', 'Second', 'fallback', 0, 'pinned', 20),\
                    ('01a041c1-1c25-7400-94cc-5efd2517517d', 'First', 'fallback', 0, 'pinned', 10),\
                    ('01a041e1-5e15-78e1-b323-641ec611a480', 'Archived', 'fallback', 1, 'pinned', 5);",
            )
            .unwrap();

        let pinned = read_pinned_threads(&connection);
        assert_eq!(
            pinned
                .iter()
                .map(|thread| thread.title.as_str())
                .collect::<Vec<_>>(),
            vec!["First", "Second"]
        );
    }

    #[test]
    fn session_index_latest_title_overrides_older_entries() {
        let input = concat!(
            "{\"id\":\"01a01d62-922b-7e92-9c45-7dba39a63e55\",",
            "\"thread_name\":\"Bath towel designs\"}\n",
            "not json\n",
            "{\"id\":\"01a01d62-922b-7e92-9c45-7dba39a63e55\",",
            "\"thread_name\":\"Bath towel designs [2]\"}\n",
        );
        let thread = ThreadKey::parse("01a01d62-922b-7e92-9c45-7dba39a63e55").unwrap();

        assert_eq!(
            read_session_index_titles(std::io::Cursor::new(input))
                .get(&thread)
                .map(String::as_str),
            Some("Bath towel designs [2]")
        );
    }
}
