use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthorizedDevice {
    pub device_id: String,
    pub public_key: String,
    pub added_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizedKeysFile {
    #[serde(default)]
    devices: Vec<AuthorizedDevice>,
}

#[derive(Clone)]
pub struct AuthorizedKeysStore {
    path: PathBuf,
    devices: Arc<RwLock<HashMap<String, AuthorizedDevice>>>,
}

impl AuthorizedKeysStore {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let devices = load_devices_map(&path)?;
        Ok(Self {
            path,
            devices: Arc::new(RwLock::new(devices)),
        })
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        let new_devices = load_devices_map(&self.path)?;
        let mut guard = self
            .devices
            .write()
            .map_err(|_| anyhow::anyhow!("authorized keys store lock poisoned"))?;
        *guard = new_devices;
        Ok(())
    }

    pub fn is_authorized(&self, public_key: &str) -> bool {
        self.devices
            .read()
            .map(|devices| devices.contains_key(public_key))
            .unwrap_or(false)
    }

    pub fn device_count(&self) -> usize {
        self.devices
            .read()
            .map(|devices| devices.len())
            .unwrap_or(0)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn load_devices_map(path: &Path) -> anyhow::Result<HashMap<String, AuthorizedDevice>> {
    let raw = fs::read_to_string(path)?;
    let parsed: AuthorizedKeysFile = toml::from_str(&raw)?;
    let devices = parsed
        .devices
        .into_iter()
        .map(|device| (device.public_key.clone(), device))
        .collect();
    Ok(devices)
}

pub struct AuthorizedKeysWatcher {
    _watcher: RecommendedWatcher,
}

impl AuthorizedKeysWatcher {
    pub fn spawn(store: AuthorizedKeysStore) -> notify::Result<Self> {
        let path = store.path().to_path_buf();
        let path_for_callback = path.clone();
        let mut watcher = notify::recommended_watcher(move |event_result| match event_result {
            Ok(_event) => {
                if let Err(err) = store.reload() {
                    error!(path = %path_for_callback.display(), error = %err, "authorized keys reload failed");
                } else {
                    info!(path = %path_for_callback.display(), devices = store.device_count(), "authorized keys reloaded");
                }
            }
            Err(err) => {
                warn!(path = %path_for_callback.display(), error = %err, "authorized keys watcher event error");
            }
        })?;

        watcher.watch(&path, RecursiveMode::NonRecursive)?;
        Ok(Self { _watcher: watcher })
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizedKeysStore;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
    }

    #[test]
    fn store_loads_authorized_keys_file() {
        let path = temp_file_path("authorized-keys");
        fs::write(
            &path,
            r#"[[devices]]
device_id = "android-phone"
public_key = "pub-a"
added_at = "2026-03-31T00:00:00Z"

[[devices]]
device_id = "linux-cli"
public_key = "pub-b"
"#,
        )
        .expect("test file should be written");

        let store = AuthorizedKeysStore::load(&path).expect("store should load");
        assert_eq!(store.device_count(), 2);
        assert!(store.is_authorized("pub-a"));
        assert!(store.is_authorized("pub-b"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_reflects_file_changes() {
        let path = temp_file_path("authorized-reload");
        fs::write(
            &path,
            r#"[[devices]]
device_id = "android-phone"
public_key = "pub-a"
"#,
        )
        .expect("initial test file should be written");

        let store = AuthorizedKeysStore::load(&path).expect("store should load");
        assert!(store.is_authorized("pub-a"));
        assert!(!store.is_authorized("pub-b"));

        fs::write(
            &path,
            r#"[[devices]]
device_id = "linux-cli"
public_key = "pub-b"
"#,
        )
        .expect("updated test file should be written");

        store.reload().expect("reload should succeed");
        assert!(!store.is_authorized("pub-a"));
        assert!(store.is_authorized("pub-b"));

        let _ = fs::remove_file(path);
    }
}
