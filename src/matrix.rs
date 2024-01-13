use crate::ArgsLogin;
use crate::store::PwsafeStore;

use eyre::Report;
use matrix_sdk::{AuthSession, Client, config::StoreConfig, matrix_auth::MatrixSession};
use tokio::process;

pub struct ClientSession {
    pub client: Client,
    pub session: MatrixSession,
}

pub async fn create_session(
    args: Option<&ArgsLogin>,
    session: Option<MatrixSession>,
    state_store: PwsafeStore,
)
    -> Result<ClientSession, Report>
{
    let username;
    let client = if let Some(a) = args {
        username = a.user.clone();
        Client::builder()
            .homeserver_url(&a.homeserver)
            .build()
            .await?
    } else if let Some(s) = session.as_ref() {
        username = s.meta.user_id.localpart().to_owned();
        let store_config = StoreConfig::new().crypto_store(state_store);

        Client::builder()
            .store_config(store_config)
            .server_name(s.meta.user_id.server_name())
            .build()
            .await?
    } else {
        return Err(Report::msg("Login found neither stored session, nor homeserver"));
    };

    if let Some(session) = session {
        if client.restore_session(session).await.is_ok() {
            let session = client.session().unwrap();
            let AuthSession::Matrix(session) = session else {
                return Err(Report::msg("Bad Login, found no matrix session"));
            };

            return Ok(ClientSession {
                client,
                session,
            });
        }
    }

    let given_password = args.and_then(|a| a.password.as_ref());
    let enforce_tty = args.map_or(true, |a| !a.not_from_tty);

    let passwd = match given_password {
        Some(passwd) => passwd.as_bytes().to_vec(),
        None if enforce_tty && passterm::isatty(passterm::Stream::Stdin) => {
            passterm::prompt_password_stdin(None, passterm::Stream::Stderr)?.into_bytes()
        }
        _ => {
            if let Some(askpass) = std::env::var_os("PWSAFE_MATRIX_ASKPASS") {
                let output = process::Command::new(askpass)
                    .stdin(std::process::Stdio::piped())
                    .output()
                    .await?;

                if !output.status.success() {
                    return Err(Report::msg("Login via password failed to ask the `PWSAFE_MATRIX_ASKPASS` program"));
                }

                output.stdout
            } else {
                return Err(Report::msg("Login via password required but no password provided"));
            }
        }
    };

    let passwd = core::str::from_utf8(&passwd)?;

    client
        .matrix_auth()
        .login_username(&username, passwd)
        .initial_device_display_name("passwd-matrix-bot")
        .send()
        .await?;

    let session = client.session().unwrap();
    let AuthSession::Matrix(session) = session else {
        return Err(Report::msg("Bad Login, found no matrix session"));
    };

    Ok(ClientSession {
        client,
        session,
    })
}
