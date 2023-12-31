use crate::ArgsLogin;

use eyre::Report;
use matrix_sdk::{Client, Session};
use tokio::process;

pub struct ClientSession {
    pub client: Client,
    pub session: Session,
}

pub async fn create_session(
    args: Option<&ArgsLogin>,
    session: Option<Session>
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
        username = s.user_id.localpart().to_owned();
        Client::builder()
            .server_name(s.user_id.server_name())
            .build()
            .await?
    } else {
        return Err(Report::msg("Login found neither stored session, nor homeserver"));
    };

    if let Some(session) = session {
        if client.restore_login(session).await.is_ok() {
            let session = client.session().unwrap();
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
    client.login_username(&username, passwd).send().await?;
    let session = client.session().unwrap();

    Ok(ClientSession {
        client,
        session,
    })
}
