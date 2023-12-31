use crate::ArgsLogin;

use eyre::Report;
use matrix_sdk::{Client, Session};
use tokio::process;

pub struct ClientSession {
    pub client: Client,
    pub session: Session,
}

pub async fn create_session(args: &ArgsLogin, session: Option<Session>)
    -> Result<ClientSession, Report>
{
    let client = Client::builder()
        .homeserver_url(&args.homeserver)
        .build()
        .await?;

    if let Some(session) = session {
        if client.restore_login(session).await.is_ok() {
            let session = client.session().unwrap();
            return Ok(ClientSession {
                client,
                session,
            });
        }
    }

    let passwd = match &args.password {
        Some(passwd) => passwd.as_bytes().to_vec(),
        None if !args.not_from_tty && passterm::isatty(passterm::Stream::Stdin) => {
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
    client.login_username(&args.user, passwd).send().await?;
    let session = client.session().unwrap();

    Ok(ClientSession {
        client,
        session,
    })
}
