use crate::provider::Provider;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self { providers: HashMap::new() }
    }

    pub fn register(&mut self, provider: Box<dyn Provider>) {
        let kind = provider.kind().to_string();
        if self.providers.insert(kind.clone(), provider).is_some() {
            tracing::warn!(kind = %kind, "provider re-registered, previous overwritten");
        }
    }

    pub fn get(&self, kind: &str) -> Option<&dyn Provider> {
        self.providers.get(kind).map(std::convert::AsRef::as_ref)
    }

    pub fn require(&self, kind: &str) -> crate::Result<&dyn Provider> {
        self.get(kind).ok_or_else(|| crate::Error::UnknownKind(kind.to_string()))
    }

    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }
}
