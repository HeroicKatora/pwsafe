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

#[test]
fn parse() {
    const INFO: &[u8] = &[
        0, 53, 101, 101, 97, 55, 55, 100, 56, 48, 99, 48, 97, 55, 52, 56, 98, 47, 117, 110, 105,
        116, 47, 109, 121, 45, 116, 105, 109, 101, 114, 45, 105, 115, 45, 97, 119, 101, 115, 111,
        109, 101, 46, 115, 101, 114, 118, 105, 99, 101, 47, 119, 97, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let info = super::parse_peer_addr(INFO).expect("Valid address information from systemd");
    assert_eq!(info.service, "my-timer-is-awesome.service");
    assert_eq!(info.credential, "wat");
}
