use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct Configuration {
    credentials: HashMap<String, CredentialSource>,
}

#[derive(Deserialize)]
pub enum CredentialSource {
    ByUuid(String),
}
