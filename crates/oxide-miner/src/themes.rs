// OxideMiner/crates/oxide-miner/src/themes.rs

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeKind {
    BuiltIn,
    Plugin,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThemeResponseEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_css_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entry_js_urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_html_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_url: Option<String>,
    pub kind: ThemeKind,
}

#[derive(Debug, Clone)]
pub struct ThemeEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub entry_css: Option<String>,
    pub entry_js: Vec<String>,
    pub entry_html: Option<String>,
    pub preview_image: Option<String>,
    pub root: Option<PathBuf>,
    pub kind: ThemeKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase", untagged)]
enum JsEntry {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct ThemeManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub entry_css: String,
    #[serde(default)]
    pub entry_js: Option<JsEntry>,
    pub entry_html: Option<String>,
    pub preview_image: Option<String>,
}

fn is_valid_id(id: &str) -> bool {
    let len = id.len();
    if !(1..=64).contains(&len) {
        return false;
    }
    id.chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
}

fn safe_relative_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return None;
    }
    let mut cleaned = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(part) => cleaned.push(part),
            Component::CurDir => continue,
            _ => return None,
        }
    }
    cleaned.to_str().map(|s| s.replace('\\', "/"))
}

fn ensure_within_root(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let canon_root = root.canonicalize().ok()?;
    let canon_candidate = candidate.canonicalize().ok()?;
    if canon_candidate.starts_with(&canon_root) {
        Some(canon_candidate)
    } else {
        None
    }
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("theme.json")
}

fn detect_preview(dir: &Path) -> Option<String> {
    for name in ["preview.png", "preview.jpg", "preview.jpeg"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(name.to_string());
        }
    }
    None
}

fn read_manifest(dir: &Path) -> Option<ThemeEntry> {
    let manifest_path = manifest_path(dir);
    let contents = fs::read_to_string(&manifest_path).ok()?;
    let manifest: ThemeManifest = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("Invalid theme manifest {:?}: {err}", manifest_path);
            return None;
        }
    };

    if !is_valid_id(&manifest.id) {
        tracing::warn!("Theme id '{}' is invalid", manifest.id);
        return None;
    }

    let folder_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if manifest.id != folder_name {
        tracing::warn!(
            "Theme id '{}' does not match folder name '{}'",
            manifest.id,
            folder_name
        );
        return None;
    }

    let entry_css = match safe_relative_path(&manifest.entry_css) {
        Some(p) => p,
        None => {
            tracing::warn!("Theme '{}' has unsafe entry_css path", manifest.id);
            return None;
        }
    };

    let entry_css_path = dir.join(&entry_css);
    if !entry_css_path.is_file() {
        tracing::warn!("Theme '{}' missing entry_css file: {}", manifest.id, entry_css);
        return None;
    }

    let entry_js = match manifest.entry_js {
        Some(JsEntry::Single(v)) => vec![v],
        Some(JsEntry::Multiple(list)) => list,
        None => Vec::new(),
    };

    let mut sanitized_js = Vec::new();
    for js in entry_js {
        if let Some(safe) = safe_relative_path(&js) {
            if dir.join(&safe).is_file() {
                sanitized_js.push(safe);
            } else {
                tracing::warn!("Theme '{}' missing JS file: {}", manifest.id, js);
                return None;
            }
        } else {
            tracing::warn!("Theme '{}' has unsafe JS path: {}", manifest.id, js);
            return None;
        }
    }

    let entry_html = if let Some(html) = manifest.entry_html {
        match safe_relative_path(&html) {
            Some(safe) => {
                let path = dir.join(&safe);
                if path.is_file() {
                    Some(safe)
                } else {
                    tracing::warn!("Theme '{}' missing HTML file: {}", manifest.id, html);
                    return None;
                }
            }
            None => {
                tracing::warn!("Theme '{}' has unsafe HTML path: {}", manifest.id, html);
                return None;
            }
        }
    } else {
        None
    };

    let preview_image = if let Some(manifest_preview) = manifest.preview_image {
        match safe_relative_path(&manifest_preview) {
            Some(safe) => {
                let path = dir.join(&safe);
                if path.is_file() {
                    Some(safe)
                } else {
                    tracing::warn!("Theme '{}' missing preview image: {}", manifest.id, manifest_preview);
                    detect_preview(dir)
                }
            }
            None => {
                tracing::warn!("Theme '{}' has unsafe preview path: {}", manifest.id, manifest_preview);
                detect_preview(dir)
            }
        }
    } else {
        detect_preview(dir)
    };

    Some(ThemeEntry {
        id: manifest.id,
        name: manifest.name,
        version: manifest.version,
        description: manifest.description,
        author: manifest.author,
        license: manifest.license,
        entry_css: Some(entry_css),
        entry_js: sanitized_js,
        entry_html,
        preview_image,
        root: Some(dir.to_path_buf()),
        kind: ThemeKind::Plugin,
    })
}

fn built_in_theme(id: &str, name: &str, description: &str) -> ThemeEntry {
    ThemeEntry {
        id: id.to_string(),
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: Some(description.to_string()),
        author: Some("OxideMiner".to_string()),
        license: Some("MIT".to_string()),
        entry_css: None,
        entry_js: Vec::new(),
        entry_html: None,
        preview_image: None,
        root: None,
        kind: ThemeKind::BuiltIn,
    }
}

fn discover_dir(theme_dir: &Path) -> Vec<ThemeEntry> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(theme_dir) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("Unable to read themes directory {:?}: {err}", theme_dir);
            return entries;
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = manifest_path(&path);
        if !manifest_path.is_file() {
            tracing::warn!("Skipping theme without manifest: {:?}", path);
            continue;
        }
        if let Some(theme) = read_manifest(&path) {
            entries.push(theme);
        }
    }

    entries
}

fn resolve_theme_dir(override_dir: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(dir) = override_dir {
        if dir.is_dir() {
            return Some(dir);
        }
    }

    if let Ok(cwd) = env::current_dir() {
        let candidate = cwd.join("plugins").join("themes");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("plugins").join("themes");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }

    None
}

#[derive(Debug, Default, Clone)]
pub struct ThemeCatalog {
    entries: Vec<ThemeEntry>,
    index: HashMap<String, usize>,
}

impl ThemeCatalog {
    pub fn discover(override_dir: Option<PathBuf>) -> Self {
        let mut entries = vec![
            built_in_theme("light", "Light", "Built-in light dashboard theme"),
            built_in_theme("dark", "Dark", "Built-in dark dashboard theme"),
            built_in_theme("monero", "Monero", "Built-in Monero-inspired theme"),
        ];

        let theme_dir = resolve_theme_dir(override_dir.clone());
        if let Some(dir) = theme_dir.as_ref() {
            entries.extend(discover_dir(dir));
        }

        entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.id.cmp(&b.id)));

        let mut index = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            index.insert(entry.id.clone(), idx);
        }

        ThemeCatalog { entries, index }
    }

    pub fn to_response(&self) -> Vec<ThemeResponseEntry> {
        let base = "/plugins/themes";
        self.entries
            .iter()
            .map(|t| ThemeResponseEntry {
                id: t.id.clone(),
                name: t.name.clone(),
                version: t.version.clone(),
                description: t.description.clone(),
                author: t.author.clone(),
                license: t.license.clone(),
                entry_css_url: t
                    .entry_css
                    .as_ref()
                    .map(|p| format!("{}/{}/{}", base, t.id, p)),
                entry_js_urls: t
                    .entry_js
                    .iter()
                    .map(|p| format!("{}/{}/{}", base, t.id, p))
                    .collect(),
                entry_html_url: t
                    .entry_html
                    .as_ref()
                    .map(|p| format!("{}/{}/{}", base, t.id, p)),
                preview_url: t
                    .preview_image
                    .as_ref()
                    .map(|p| format!("{}/{}/{}", base, t.id, p)),
                kind: t.kind.clone(),
            })
            .collect()
    }

    pub fn resolve_asset(&self, theme_id: &str, rel_path: &str) -> Option<PathBuf> {
        let idx = *self.index.get(theme_id)?;
        let entry = self.entries.get(idx)?;
        let root = entry.root.as_ref()?;
        let safe_rel = safe_relative_path(rel_path)?;
        let full = root.join(&safe_rel);
        ensure_within_root(root, &full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_manifest(dir: &Path, manifest: &str) {
        fs::write(dir.join("theme.json"), manifest).unwrap();
    }

    #[test]
    fn validate_ids() {
        assert!(is_valid_id("abc"));
        assert!(is_valid_id("a.b-c_1"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("UPPER"));
        assert!(!is_valid_id("toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong"));
        assert!(!is_valid_id("bad/.."));
    }

    #[test]
    fn sanitize_paths() {
        assert_eq!(safe_relative_path("ok/file.css").as_deref(), Some("ok/file.css"));
        assert!(safe_relative_path("../bad").is_none());
        assert!(safe_relative_path("/abs").is_none());
        assert!(safe_relative_path("").is_none());
    }

    #[test]
    fn detects_preview_fallback() {
        let dir = tempdir().unwrap();
        let theme_dir = dir.path().join("blue");
        fs::create_dir_all(&theme_dir).unwrap();
        fs::write(theme_dir.join("theme.css"), "/* css */").unwrap();
        fs::write(theme_dir.join("preview.jpg"), "img").unwrap();
        write_manifest(
            &theme_dir,
            r#"{
            "id": "blue",
            "name": "Blue",
            "version": "1.0.0",
            "entry_css": "theme.css"
        }"#,
        );

        let entry = read_manifest(&theme_dir).expect("manifest");
        assert_eq!(entry.preview_image.as_deref(), Some("preview.jpg"));
    }

    #[test]
    fn rejects_traversal_manifest() {
        let dir = tempdir().unwrap();
        let theme_dir = dir.path().join("bad");
        fs::create_dir_all(&theme_dir).unwrap();
        fs::write(theme_dir.join("theme.css"), "/* css */").unwrap();
        write_manifest(
            &theme_dir,
            r#"{
            "id": "bad",
            "name": "Bad",
            "version": "1.0.0",
            "entry_css": "../theme.css"
        }"#,
        );

        assert!(read_manifest(&theme_dir).is_none());
    }

    #[test]
    fn resolves_assets_safely() {
        let dir = tempdir().unwrap();
        let theme_dir = dir.path().join("safe");
        fs::create_dir_all(theme_dir.join("assets")).unwrap();
        fs::write(theme_dir.join("assets").join("theme.css"), "/* css */").unwrap();
        write_manifest(
            &theme_dir,
            r#"{
            "id": "safe",
            "name": "Safe",
            "version": "1.0.0",
            "entry_css": "assets/theme.css"
        }"#,
        );

        let catalog = ThemeCatalog::discover(Some(dir.path().to_path_buf()));
        let asset = catalog.resolve_asset("safe", "assets/theme.css");
        assert!(asset.is_some());
        let traversal = catalog.resolve_asset("safe", "../theme.css");
        assert!(traversal.is_none());
    }

    #[test]
    fn rejects_missing_js() {
        let dir = tempdir().unwrap();
        let theme_dir = dir.path().join("missing");
        fs::create_dir_all(&theme_dir).unwrap();
        fs::write(theme_dir.join("theme.css"), "/* css */").unwrap();
        write_manifest(
            &theme_dir,
            r#"{
            "id": "missing",
            "name": "Missing",
            "version": "1.0.0",
            "entry_css": "theme.css",
            "entry_js": "missing.js"
        }"#,
        );

        assert!(read_manifest(&theme_dir).is_none());
    }
}
