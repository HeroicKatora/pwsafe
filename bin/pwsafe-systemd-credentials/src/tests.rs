use pwsafer::PwsafeKey;
use tokio;

use crate::SystemdUnitSource;
use std::sync::{atomic::AtomicBool, Arc};

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
    local.spawn_local(unlock(store, cfg.clone(), read_password_fake));

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

#[tokio::main]
#[test]
async fn check_wrong_password_timeout() -> std::io::Result<()> {
    async fn with_password_error(wrong: &mut Option<String>) -> std::io::Result<PwsafeKey> {
        if let Some(wrong) = wrong.take() {
            Ok(PwsafeKey::new(wrong.as_bytes()))
        } else {
            Ok(PwsafeKey::new(b"password"))
        }
    }

    let configuration = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/configuration.json");
    let pwsafe = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pwsafe.psafe3");

    let cfg = tokio::fs::read_to_string(configuration).await?;
    let mut cfg = configuration::Configuration::from_str(&cfg)?;
    cfg.password_retry = 0.1;
    let cfg = std::sync::Arc::new(cfg);

    let store = pwfile::Passwords::new(pwsafe.into()).await?;
    let reader = store.reader();

    let local = tokio::task::LocalSet::new();
    let mut oopsie = Some("not-the-right-password".to_string());
    local.spawn_local(unlock(store, cfg.clone(), move || {
        let mut oopsie = oopsie.take();
        async move { with_password_error(&mut oopsie).await }
    }));

    let systemd = SystemdUnitSource {
        credential: "testcredential".to_string(),
        service: "dummy.service".to_string(),
    };

    let reader = reader.clone();
    let cfg = cfg.clone();

    let start = std::time::Instant::now();
    let minimum_time = cfg.password_retry;

    let entry = local
        .run_until(answer_request(&systemd, reader, cfg))
        .await?;

    assert_eq!(entry, Some(b"test".to_vec()));
    assert!(start.elapsed().as_secs_f32() >= minimum_time);

    Ok(())
}

#[tokio::main]
#[test]
async fn relocks() -> std::io::Result<()> {
    async fn read_password_fake(
        okay: Option<PwsafeKey>,
        stalled: Arc<AtomicBool>,
    ) -> std::io::Result<PwsafeKey> {
        if let Some(pw) = okay {
            return Ok(pw);
        }

        stalled.fetch_or(true, std::sync::atomic::Ordering::Relaxed);

        loop {
            tokio::task::yield_now().await;
        }
    }

    let configuration = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/configuration.json");
    let pwsafe = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pwsafe.psafe3");

    let cfg = tokio::fs::read_to_string(configuration).await?;
    let mut cfg = configuration::Configuration::from_str(&cfg)?;
    cfg.password_lock = 0.05;

    let cfg = std::sync::Arc::new(cfg);

    let store = pwfile::Passwords::new(pwsafe.into()).await?;
    let reader = store.reader();

    let local = tokio::task::LocalSet::new();
    let mut restricted_to_once = Some(PwsafeKey::new(b"password"));
    let we_have_sent = Arc::new(AtomicBool::default());
    let check_have_stalled = we_have_sent.clone();

    local.spawn_local(unlock(store, cfg.clone(), move || {
        let restricted_to_once = restricted_to_once.take();
        let we_have_sent = we_have_sent.clone();
        async { read_password_fake(restricted_to_once, we_have_sent).await }
    }));

    let systemd = SystemdUnitSource {
        credential: "testcredential".to_string(),
        service: "dummy.service".to_string(),
    };

    let entry = local
        .run_until({
            let reader = reader.clone();
            let cfg = cfg.clone();

            answer_request(&systemd, reader, cfg)
        })
        .await?;
    assert_eq!(entry, Some(b"test".to_vec()));

    // Sure so this should be unlocked now. Check that a few secs later it is no longer unlocked.
    let is_to = local
        .run_until(async {
            let reader = reader.clone();
            let cfg = cfg.clone();

            let lock_time = std::time::Duration::from_secs_f32(2. * cfg.password_lock);
            tokio::time::sleep(lock_time).await;

            tokio::time::timeout(lock_time, answer_request(&systemd, reader, cfg)).await
        })
        .await;
    assert!(is_to.is_err());
    assert!(check_have_stalled.load(std::sync::atomic::Ordering::Relaxed));

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
