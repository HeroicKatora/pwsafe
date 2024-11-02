use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct Configuration {
    pub credentials: HashMap<String, CredentialSource>,
    #[serde(default = "Configuration::default_retry")]
    pub password_retry: f32,
}

#[derive(Deserialize)]
pub enum CredentialSource {
    ByUuid(uuid::Uuid),
}

impl Configuration {
    fn default_retry() -> f32 {
        3.0
    }

    pub fn from_str(data: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(data)
    }
}
