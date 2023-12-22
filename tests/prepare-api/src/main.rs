use std::fs::File;
use serde::{Deserialize, Serialize};

fn main() -> Result<(), anyhow::Error> {
    // Get the shared secret..
    let homeserver = HomeServer::new()?;

    let agent = ureq::AgentBuilder::new()
        .build();

    let nonce = {
        let response = agent.get("http://localhost:8080/_synapse/admin/v1/register")
            .send_bytes(b"")?;

        let mut body = vec![];
        response.into_reader().read_to_end(&mut body)?;

        let RegisterNonce { nonce } = serde_json::from_slice(&body)?;
        nonce
    };

    let user = UserForNonceRegistration {
        nonce,
        username: "example".to_string(),
        displayname: "Example Is Good".to_string(),
        password: "should-be-random-but-is-just-long".to_string(),
        admin: false,
    };

    let mac = homeserver.mac(&user);
    let register = Register { user, mac };
    let encode = serde_json::to_string(&register)?;

    let response = agent.post("http://localhost:8080/_synapse/admin/v1/register")
        .send_string(&encode)?;

    eprintln!("{response:?}");
    Ok(())
}

#[derive(Deserialize)]
struct HomeServer {
    registration_shared_secret: String,
}

#[derive(Deserialize)]
struct RegisterNonce {
    nonce: String,
}

impl HomeServer {
    pub fn new() -> Result<Self, anyhow::Error> {
        let homeserver = File::open(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../local/data/homeserver.yaml"
            )
        )?;

        let homeserver = serde_yaml::from_reader(homeserver)?;
        Ok(homeserver)
    }

    fn mac(&self, user: &UserForNonceRegistration) -> String {
        // <https://matrix-org.github.io/synapse/latest/admin_api/register_api.html#shared-secret-registration>
        use hmac::{Hmac, Mac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let mut mac = HmacSha1::new_from_slice(self.registration_shared_secret.as_bytes())
            .expect("HMAC can take keys of any size");
        mac.update(user.nonce.as_bytes());
        mac.update(b"\0");
        mac.update(user.username.as_bytes());
        mac.update(b"\0");
        mac.update(user.password.as_bytes());
        mac.update(b"\0");
        mac.update(if user.admin { b"admin" } else { b"notadmin" });

        let mac = mac.finalize();
        let mac = mac.into_bytes();
        hex::encode(&mac[..])
    }
}

#[derive(Serialize)]
struct UserForNonceRegistration {
    nonce: String,
    username: String,
    displayname: String,
    password: String,
    admin: bool,
}

#[derive(Serialize)]
struct Register {
    #[serde(flatten)]
    user: UserForNonceRegistration,
    mac: String,
}
