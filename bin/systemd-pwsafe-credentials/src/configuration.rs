use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct Configuration {
    pub credentials: HashMap<String, CredentialSource>,
}

#[derive(Deserialize)]
pub enum CredentialSource {
    ByUuid(uuid::Uuid),
}

impl Configuration {
    pub fn from_str(data: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(data)
    }
}
