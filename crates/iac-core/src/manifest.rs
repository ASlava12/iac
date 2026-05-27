use crate::resource::{Resource, SourceLocation};
use crate::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Load a single YAML file. Supports multi-document streams (`---` separated).
pub fn load_file(path: &Path) -> Result<Vec<Resource>> {
    let bytes = std::fs::read(path).map_err(|e| Error::Io {
        path: path.into(),
        source: e,
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| Error::manifest(path, format!("not valid utf-8: {e}")))?;
    parse_documents(path, text)
}

/// Parse a multi-document YAML stream into a list of [`Resource`].
/// Public so fuzz tests in downstream crates can drive it directly.
/// `path` is used only for error messages.
pub fn parse_documents(path: &Path, text: &str) -> Result<Vec<Resource>> {
    let mut out = Vec::new();
    for (idx, doc) in serde_yaml_ng::Deserializer::from_str(text).enumerate() {
        let value = serde_yaml_ng::Value::deserialize(doc).map_err(|e| Error::Yaml {
            path: path.into(),
            source: e,
        })?;
        // Skip empty documents (e.g. trailing `---\n`).
        if value.is_null() {
            continue;
        }
        let mut resource: Resource = serde_yaml_ng::from_value(value).map_err(|e| Error::Yaml {
            path: path.into(),
            source: e,
        })?;
        resource.source = SourceLocation {
            file: path.to_path_buf(),
            document_index: idx,
        };
        resource.validate_shape()?;
        out.push(resource);
    }
    Ok(out)
}

/// Load all `.yaml` / `.yml` files under a directory, recursively.
pub fn load_directory(root: &Path) -> Result<Vec<Resource>> {
    let mut out = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("walk error: {e}"));
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|ext| matches!(ext, "yaml" | "yml"));
        if !is_yaml {
            continue;
        }
        match load_file(path) {
            Ok(mut rs) => out.append(&mut rs),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
    if !errors.is_empty() {
        return Err(Error::manifest(
            PathBuf::from(root),
            format!(
                "{} file(s) failed to load:\n  - {}",
                errors.len(),
                errors.join("\n  - ")
            ),
        ));
    }
    Ok(out)
}

/// Convenience: file or directory.
pub fn load_path(path: &Path) -> Result<Vec<Resource>> {
    let meta = std::fs::metadata(path).map_err(|e| Error::Io {
        path: path.into(),
        source: e,
    })?;
    if meta.is_dir() {
        load_directory(path)
    } else {
        load_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_single_doc() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
apiVersion: iac.example/v1
kind: file
metadata:
  name: hello
  environment: test
spec:
  path: /tmp/hello
"#
        )
        .unwrap();
        let rs = load_file(f.path()).unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].kind, "file");
        assert_eq!(rs[0].metadata.name, "hello");
    }

    #[test]
    fn loads_multi_doc() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
apiVersion: iac.example/v1
kind: file
metadata:
  name: a
  environment: test
spec:
  path: /tmp/a
---
apiVersion: iac.example/v1
kind: file
metadata:
  name: b
  environment: test
spec:
  path: /tmp/b
"#
        )
        .unwrap();
        let rs = load_file(f.path()).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].metadata.name, "a");
        assert_eq!(rs[1].metadata.name, "b");
    }

    #[test]
    fn rejects_missing_name() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
apiVersion: iac.example/v1
kind: file
metadata:
  name: ""
spec:
  path: /tmp/x
"#
        )
        .unwrap();
        let err = load_file(f.path()).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }
}
