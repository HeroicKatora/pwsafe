use crate::{ArgsCreateRoom, ArgsLogin, ArgsPwsafe};
use crate::matrix::create_session;
use crate::pwsafe::PwsafeDb;

use matrix_sdk::ruma::{
    api::client::room::{
        create_room,
        Visibility,
    },
    events::{
        EmptyStateKey,
        InitialStateEvent,
        room::encryption::RoomEncryptionEventContent,
    },
    EventEncryptionAlgorithm,
};

use eyre::Report;

pub async fn run(
    pwsafe: ArgsPwsafe,
    login: ArgsLogin,
    room: ArgsCreateRoom,
) -> Result<(), Report> {
    let mut db = PwsafeDb::open(&pwsafe)?;

    if db.session().is_some() && !room.force {
        return Err(Report::msg("Pwsafe file already contains pwsafe-matrix information, use `--force` to overwrite"));
    }

    let cs = create_session(Some(&login), None).await?;

    let room_id = {
        let mut create = create_room::v3::Request::default();

        let encrypt = RoomEncryptionEventContent::new(EventEncryptionAlgorithm::MegolmV1AesSha2);
        let event = InitialStateEvent {
            content: encrypt,
            state_key: EmptyStateKey,
        };
        let event = matrix_sdk::ruma::serde::Raw::new(&event)?.cast();
        let initial_event = vec![event];

        create.visibility = Visibility::Private;
        create.initial_state = &initial_event;

        let response = cs.client.create_room(create).await?;
        response.room_id
    };

    db.set_session(cs.session);
    db.set_room(room_id);

    db.with_lock(|mut lock| {
        lock.rewrite()
    })?;

    Ok(())
}
