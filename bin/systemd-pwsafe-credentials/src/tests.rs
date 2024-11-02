use pwsafer::PwsafeKey;
use tokio;

use crate::SystemdUnitSource;

use super::{answer_request, configuration, pwfile, unlock};

#[tokio::main]
#[test]
async fn with_io() -> std::io::Result<()> {
    async fn read_password_fake() -> std::io::Result<PwsafeKey> {
        Ok(PwsafeKey::new(b"password"))
    }

    let configuration = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/configuration.json");
    let pwsafe = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pwsafe.psafe3");

    let cfg = tokio::fs::read_to_string(configuration).await?;
    let cfg = configuration::Configuration::from_str(&cfg)?;
    let cfg = std::sync::Arc::new(cfg);

    let store = pwfile::Passwords::new(pwsafe.into()).await?;
    let reader = store.reader();

    let local = tokio::task::LocalSet::new();
    local.spawn_local(unlock(store, read_password_fake));

    let systemd = SystemdUnitSource {
        credential: "testcredential".to_string(),
        service: "dummy.service".to_string(),
    };

    let reader = reader.clone();
    let cfg = cfg.clone();

    let entry = local
        .run_until(answer_request(&systemd, reader, cfg))
        .await?;

    assert_eq!(entry, Some(b"test".to_vec()));

    Ok(())
}
