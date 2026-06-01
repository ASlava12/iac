use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("yaml parse error in {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("manifest error in {path}: {message}")]
    Manifest { path: PathBuf, message: String },

    #[error("validation failed for {resource}: {message}")]
    Validation { resource: String, message: String },

    #[error("unknown resource kind: {0}")]
    UnknownKind(String),

    #[error("provider {provider} failed: {message}")]
    Provider { provider: String, message: String },

    #[error("checkpoint missing for resource {resource}: {message}")]
    Checkpoint { resource: String, message: String },

    #[error("command failed: {0}")]
    Command(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn validation(resource: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            resource: resource.into(),
            message: message.into(),
        }
    }

    pub fn manifest(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Manifest {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn provider(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Provider {
            provider: name.into(),
            message: message.into(),
        }
    }
}
