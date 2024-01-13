use std::collections::HashMap;
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use matrix_sdk::crypto as matrix_sdk_crypto;
use tokio::{sync::Mutex, time::Instant};

use matrix_sdk_crypto::{
    olm::{
        Account,
        InboundGroupSession,
        OlmMessageHash,
        OutboundGroupSession,
        PickledAccount,
        PickledCrossSigningIdentity,
        PrivateCrossSigningIdentity,
        Session,
    },
    store::{
        BackupKeys,
        BackupDecryptionKey,
        Changes,
        CryptoStore,
        RoomKeyCounts,
        RoomSettings,
        PendingChanges,
    },
    types::{
        events::{
            room_key_withheld::RoomKeyWithheldEvent,
        },
    },
    CryptoStoreError,
    GossipRequest,
    GossippedSecret,
    ReadOnlyDevice,
    ReadOnlyUserIdentities,
    ReadOnlyUserIdentity,
    SecretInfo,
    TrackedUser,
};

use matrix_sdk::ruma::{
    DeviceId,
    OwnedDeviceId,
    OwnedRoomId,
    OwnedUserId,
    RoomId,
    TransactionId,
    UserId,
    events::secret::request::SecretName,
};

#[derive(Debug)]
struct PwsafeStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
struct Inner {
    account: Option<serde_json::Value>,
    identity: Option<serde_json::Value>,
    backup_decryption_key: Option<[u8; 32]>,
    backup_version: Option<String>,
    custom: HashMap<String, Vec<u8>>,
    #[serde(skip)]
    locks: Locks,
}

#[derive(Default, Debug)]
struct Locks {
    maybe_held: HashMap<String, (String, Instant)>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CryptoStore for PwsafeStore {
    /// The error type used by this crypto store.
    type Error = CryptoStoreError;

    /// Load an account that was previously stored.
    async fn load_account(&self) -> Result<Option<Account>, Self::Error> {
        let lock = self.inner.lock().await;
        let Some(account) = lock.account.as_ref() else {
            return Ok(None);
        };

        let account: PickledAccount = serde_json::from_value(account.clone())?;
        let account = Account::from_pickle(account)?;
        Ok(Some(account))
    }

    /// Try to load a private cross signing identity, if one is stored.
    async fn load_identity(&self) -> Result<Option<PrivateCrossSigningIdentity>, Self::Error> {
        let lock = self.inner.lock().await;
        let Some(identity) = lock.identity.as_ref() else {
            return Ok(None);
        };

        let identity: PickledCrossSigningIdentity = serde_json::from_value(identity.clone())?;
        let identity = PrivateCrossSigningIdentity::from_pickle(identity).await
            .expect("Woah");
        Ok(Some(identity))
    }

    /// Save the set of changes to the store.
    ///
    /// # Arguments
    ///
    /// * `changes` - The set of changes that should be stored.
    async fn save_changes(&self, changes: Changes) -> Result<(), Self::Error> {
        let Changes {
            private_identity,
            backup_version,
            backup_decryption_key,
            sessions,
            message_hashes,
            inbound_group_sessions,
            outbound_group_sessions,
            key_requests,
            identities,
            devices,
            withheld_session_info,
            room_settings,
            secrets,
            next_batch_token
        } = changes;

        todo!()
    }

    /// Save the set of changes to the store.
    ///
    /// This is an updated version of `save_changes` that will replace it as
    /// #2624 makes progress.
    ///
    /// # Arguments
    ///
    /// * `changes` - The set of changes that should be stored.
    async fn save_pending_changes(&self, changes: PendingChanges) -> Result<(), Self::Error> {
        let PendingChanges { account } = changes;
        let mut lock = self.inner.lock().await;

        if let Some(account ) = account {
            lock.account = Some(serde_json::to_value(&account.pickle())?);
        };

        Ok(())
    }

    /// Get all the sessions that belong to the given sender key.
    ///
    /// # Arguments
    ///
    /// * `sender_key` - The sender key that was used to establish the sessions.
    async fn get_sessions(
        &self,
        sender_key: &str,
    ) -> Result<Option<Arc<Mutex<Vec<Session>>>>, Self::Error> {
        todo!()
    }

    /// Get the inbound group session from our store.
    ///
    /// # Arguments
    /// * `room_id` - The room id of the room that the session belongs to.
    ///
    /// * `sender_key` - The sender key that sent us the session.
    ///
    /// * `session_id` - The unique id of the session.
    async fn get_inbound_group_session(
        &self,
        room_id: &RoomId,
        session_id: &str,
    ) -> Result<Option<InboundGroupSession>, Self::Error> {
        todo!()
    }

    /// Get withheld info for this key.
    /// Allows to know if the session was not sent on purpose.
    /// This only returns withheld info sent by the owner of the group session,
    /// not the one you can get from a response to a key request from
    /// another of your device.
    async fn get_withheld_info(
        &self,
        room_id: &RoomId,
        session_id: &str,
    ) -> Result<Option<RoomKeyWithheldEvent>, Self::Error> {
        todo!()
    }

    /// Get all the inbound group sessions we have stored.
    async fn get_inbound_group_sessions(&self) -> Result<Vec<InboundGroupSession>, Self::Error> {
        todo!()
    }

    /// Get the number inbound group sessions we have and how many of them are
    /// backed up.
    async fn inbound_group_session_counts(&self) -> Result<RoomKeyCounts, Self::Error> {
        todo!()
    }

    /// Get all the inbound group sessions we have not backed up yet.
    async fn inbound_group_sessions_for_backup(
        &self,
        limit: usize,
    ) -> Result<Vec<InboundGroupSession>, Self::Error> {
        todo!()
    }

    /// Mark the inbound group sessions with the supplied room and session IDs
    /// as backed up
    async fn mark_inbound_group_sessions_as_backed_up(
        &self,
        room_and_session_ids: &[(&RoomId, &str)],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Reset the backup state of all the stored inbound group sessions.
    async fn reset_backup_state(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Get the backup keys we have stored.
    async fn load_backup_keys(&self) -> Result<BackupKeys, Self::Error> {
        todo!()
    }

    /// Get the outbound group session we have stored that is used for the
    /// given room.
    async fn get_outbound_group_session(
        &self,
        room_id: &RoomId,
    ) -> Result<Option<OutboundGroupSession>, Self::Error> {
        todo!()
    }

    /// Load the list of users whose devices we are keeping track of.
    async fn load_tracked_users(&self) -> Result<Vec<TrackedUser>, Self::Error> {
        todo!()
    }

    /// Save a list of users and their respective dirty/outdated flags to the
    /// store.
    async fn save_tracked_users(&self, users: &[(&UserId, bool)]) -> Result<(), Self::Error> {
        todo!()
    }

    /// Get the device for the given user with the given device ID.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user that the device belongs to.
    ///
    /// * `device_id` - The unique id of the device.
    async fn get_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<Option<ReadOnlyDevice>, Self::Error> {
        todo!()
    }

    /// Get all the devices of the given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user for which we should get all the devices.
    async fn get_user_devices(
        &self,
        user_id: &UserId,
    ) -> Result<HashMap<OwnedDeviceId, ReadOnlyDevice>, Self::Error> {
        todo!()
    }

    /// Get the user identity that is attached to the given user id.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user for which we should get the identity.
    async fn get_user_identity(
        &self,
        user_id: &UserId,
    ) -> Result<Option<ReadOnlyUserIdentities>, Self::Error> {
        todo!()
    }

    /// Check if a hash for an Olm message stored in the database.
    async fn is_message_known(&self, message_hash: &OlmMessageHash) -> Result<bool, Self::Error> {
        todo!()
    }

    /// Get an outgoing secret request that we created that matches the given
    /// request id.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The unique request id that identifies this outgoing
    /// secret request.
    async fn get_outgoing_secret_requests(
        &self,
        request_id: &TransactionId,
    ) -> Result<Option<GossipRequest>, Self::Error> {
        todo!()
    }

    /// Get an outgoing key request that we created that matches the given
    /// requested key info.
    ///
    /// # Arguments
    ///
    /// * `key_info` - The key info of an outgoing secret request.
    async fn get_secret_request_by_info(
        &self,
        secret_info: &SecretInfo,
    ) -> Result<Option<GossipRequest>, Self::Error> {
        todo!()
    }

    /// Get all outgoing secret requests that we have in the store.
    async fn get_unsent_secret_requests(&self) -> Result<Vec<GossipRequest>, Self::Error> {
        todo!()
    }

    /// Delete an outgoing key request that we created that matches the given
    /// request id.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The unique request id that identifies this outgoing key
    /// request.
    async fn delete_outgoing_secret_requests(
        &self,
        request_id: &TransactionId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    /// Get all the secrets with the given [`SecretName`] we have currently
    /// stored.
    async fn get_secrets_from_inbox(
        &self,
        secret_name: &SecretName,
    ) -> Result<Vec<GossippedSecret>, Self::Error> {
        todo!()
    }

    /// Delete all the secrets with the given [`SecretName`] we have currently
    /// stored.
    async fn delete_secrets_from_inbox(&self, secret_name: &SecretName) -> Result<(), Self::Error> {
        todo!()
    }

    /// Get the room settings, such as the encryption algorithm or whether to
    /// encrypt only for trusted devices.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The room id of the room
    async fn get_room_settings(
        &self,
        room_id: &RoomId,
    ) -> Result<Option<RoomSettings>, Self::Error> {
        todo!()
    }

    /// Get arbitrary data from the store
    ///
    /// # Arguments
    ///
    /// * `key` - The key to fetch data for
    async fn get_custom_value(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        todo!()
    }

    /// Put arbitrary data into the store
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert data into
    ///
    /// * `value` - The value to insert
    async fn set_custom_value(&self, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        todo!()
    }

    /// Remove arbitrary data into the store
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert data into
    async fn remove_custom_value(&self, key: &str) -> Result<(), Self::Error> {
        todo!()
    }

    /// Try to take a leased lock.
    ///
    /// This attempts to take a lock for the given lease duration.
    ///
    /// - If we already had the lease, this will extend the lease.
    /// - If we didn't, but the previous lease has expired, we will acquire the
    ///   lock.
    /// - If there was no previous lease, we will acquire the lock.
    /// - Otherwise, we don't get the lock.
    ///
    /// Returns whether taking the lock succeeded.
    async fn try_take_leased_lock(
        &self,
        lease_duration_ms: u32,
        key: &str,
        holder: &str,
    ) -> Result<bool, Self::Error> {
        let mut lock = self.inner.lock().await;
        Ok(lock.locks.try_take(lease_duration_ms, key, holder))
    }

    /// Load the next-batch token for a to-device query, if any.
    async fn next_batch_token(&self) -> Result<Option<String>, Self::Error> {
        todo!()
    }
}

impl Locks {
    fn try_take(
        &mut self,
        lease_duration_ms: u32,
        key: &str,
        holder: &str,
    ) -> bool {
        let Some((owner, end)) = self.maybe_held.get_mut(key) else {
            let end = Instant::now() + Duration::from_millis(lease_duration_ms.into());
            let hold = (holder.to_owned(), end);
            // TODO: enforce a maximum number of locks? Reap?
            self.maybe_held.insert(key.to_owned(), hold);
            return true;
        };

        let now = Instant::now();
        if holder == owner {
            *end = now + Duration::from_millis(lease_duration_ms.into());
            true
        } else if *end < now {
            *end = now + Duration::from_millis(lease_duration_ms.into());
            *owner = holder.to_owned();
            true
        } else {
            false
        }
    }
}


/*
use matrix_sdk::{
    crypto::store::CryptoStore,
    StateStore,
    StoreError,
    ruma::{
        UserId,
        OwnedUserId,
        OwnedEventId,
        events::presence::PresenceEvent,
    },
};

use matrix_sdk_base::{
    StateStoreDataKey,
    StateStoreDataValue,
};

impl StateStore for PwsafeInnerStore {
    /// The error type used by this state store.
    type Error: fmt::Debug + Into<StoreError> + From<serde_json::Error>;

    /// Get key-value data from the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to fetch data for.
    async fn get_kv_data(
        &self,
        key: StateStoreDataKey<'_>,
    ) -> Result<Option<StateStoreDataValue>, Self::Error>;

    /// Put key-value data into the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to identify the data in the store.
    ///
    /// * `value` - The data to insert.
    ///
    /// Panics if the key and value variants do not match.
    async fn set_kv_data(
        &self,
        key: StateStoreDataKey<'_>,
        value: StateStoreDataValue,
    ) -> Result<(), Self::Error>;

    /// Remove key-value data from the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove the data for.
    async fn remove_kv_data(&self, key: StateStoreDataKey<'_>) -> Result<(), Self::Error>;

    /// Save the set of state changes in the store.
    async fn save_changes(&self, changes: &StateChanges) -> Result<(), Self::Error>;

    /// Get the stored presence event for the given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The id of the user for which we wish to fetch the presence
    /// event for.
    async fn get_presence_event(
        &self,
        user_id: &UserId,
    ) -> Result<Option<Raw<PresenceEvent>>, Self::Error>;

    /// Get the stored presence events for the given users.
    ///
    /// # Arguments
    ///
    /// * `user_ids` - The IDs of the users to fetch the presence events for.
    async fn get_presence_events(
        &self,
        user_ids: &[OwnedUserId],
    ) -> Result<Vec<Raw<PresenceEvent>>, Self::Error>;

    /// Get a state event out of the state store.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room the state event was received for.
    ///
    /// * `event_type` - The event type of the state event.
    async fn get_state_event(
        &self,
        room_id: &RoomId,
        event_type: StateEventType,
        state_key: &str,
    ) -> Result<Option<RawAnySyncOrStrippedState>, Self::Error>;

    /// Get a list of state events for a given room and `StateEventType`.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room to find events for.
    ///
    /// * `event_type` - The event type.
    async fn get_state_events(
        &self,
        room_id: &RoomId,
        event_type: StateEventType,
    ) -> Result<Vec<RawAnySyncOrStrippedState>, Self::Error>;

    /// Get a list of state events for a given room, `StateEventType`, and the
    /// given state keys.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room to find events for.
    ///
    /// * `event_type` - The event type.
    ///
    /// * `state_keys` - The list of state keys to find.
    async fn get_state_events_for_keys(
        &self,
        room_id: &RoomId,
        event_type: StateEventType,
        state_keys: &[&str],
    ) -> Result<Vec<RawAnySyncOrStrippedState>, Self::Error>;

    /// Get the current profile for the given user in the given room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The room id the profile is used in.
    ///
    /// * `user_id` - The id of the user the profile belongs to.
    async fn get_profile(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
    ) -> Result<Option<MinimalRoomMemberEvent>, Self::Error>;

    /// Get the current profiles for the given users in the given room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The ID of the room the profiles are used in.
    ///
    /// * `user_ids` - The IDs of the users the profiles belong to.
    async fn get_profiles<'a>(
        &self,
        room_id: &RoomId,
        user_ids: &'a [OwnedUserId],
    ) -> Result<BTreeMap<&'a UserId, MinimalRoomMemberEvent>, Self::Error>;

    /// Get the user ids of members for a given room with the given memberships,
    /// for stripped and regular rooms alike.
    async fn get_user_ids(
        &self,
        room_id: &RoomId,
        memberships: RoomMemberships,
    ) -> Result<Vec<OwnedUserId>, Self::Error>;

    /// Get all the user ids of members that are in the invited state for a
    /// given room, for stripped and regular rooms alike.
    #[deprecated = "Use get_user_ids with RoomMemberships::INVITE instead."]
    async fn get_invited_user_ids(&self, room_id: &RoomId)
        -> Result<Vec<OwnedUserId>, Self::Error>;

    /// Get all the user ids of members that are in the joined state for a
    /// given room, for stripped and regular rooms alike.
    #[deprecated = "Use get_user_ids with RoomMemberships::JOIN instead."]
    async fn get_joined_user_ids(&self, room_id: &RoomId) -> Result<Vec<OwnedUserId>, Self::Error>;

    /// Get all the pure `RoomInfo`s the store knows about.
    async fn get_room_infos(&self) -> Result<Vec<RoomInfo>, Self::Error>;

    /// Get all the pure `RoomInfo`s the store knows about.
    #[deprecated = "Use get_room_infos instead and filter by RoomState"]
    async fn get_stripped_room_infos(&self) -> Result<Vec<RoomInfo>, Self::Error>;

    /// Get all the users that use the given display name in the given room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room for which the display name users should
    /// be fetched for.
    ///
    /// * `display_name` - The display name that the users use.
    async fn get_users_with_display_name(
        &self,
        room_id: &RoomId,
        display_name: &str,
    ) -> Result<BTreeSet<OwnedUserId>, Self::Error>;

    /// Get all the users that use the given display names in the given room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The ID of the room to fetch the display names for.
    ///
    /// * `display_names` - The display names that the users use.
    async fn get_users_with_display_names<'a>(
        &self,
        room_id: &RoomId,
        display_names: &'a [String],
    ) -> Result<BTreeMap<&'a str, BTreeSet<OwnedUserId>>, Self::Error>;

    /// Get an event out of the account data store.
    ///
    /// # Arguments
    ///
    /// * `event_type` - The event type of the account data event.
    async fn get_account_data_event(
        &self,
        event_type: GlobalAccountDataEventType,
    ) -> Result<Option<Raw<AnyGlobalAccountDataEvent>>, Self::Error>;

    /// Get an event out of the room account data store.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room for which the room account data event
    ///   should
    /// be fetched.
    ///
    /// * `event_type` - The event type of the room account data event.
    async fn get_room_account_data_event(
        &self,
        room_id: &RoomId,
        event_type: RoomAccountDataEventType,
    ) -> Result<Option<Raw<AnyRoomAccountDataEvent>>, Self::Error>;

    /// Get an event out of the user room receipt store.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room for which the receipt should be
    ///   fetched.
    ///
    /// * `receipt_type` - The type of the receipt.
    ///
    /// * `thread` - The thread containing this receipt.
    ///
    /// * `user_id` - The id of the user for who the receipt should be fetched.
    async fn get_user_room_receipt_event(
        &self,
        room_id: &RoomId,
        receipt_type: ReceiptType,
        thread: ReceiptThread,
        user_id: &UserId,
    ) -> Result<Option<(OwnedEventId, Receipt)>, Self::Error>;

    /// Get events out of the event room receipt store.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room for which the receipts should be
    ///   fetched.
    ///
    /// * `receipt_type` - The type of the receipts.
    ///
    /// * `thread` - The thread containing this receipt.
    ///
    /// * `event_id` - The id of the event for which the receipts should be
    ///   fetched.
    async fn get_event_room_receipt_events(
        &self,
        room_id: &RoomId,
        receipt_type: ReceiptType,
        thread: ReceiptThread,
        event_id: &EventId,
    ) -> Result<Vec<(OwnedUserId, Receipt)>, Self::Error>;

    /// Get arbitrary data from the custom store
    ///
    /// # Arguments
    ///
    /// * `key` - The key to fetch data for
    async fn get_custom_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Put arbitrary data into the custom store
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert data into
    ///
    /// * `value` - The value to insert
    async fn set_custom_value(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Remove arbitrary data from the custom store and return it if existed
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove data from
    async fn remove_custom_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Add a media file's content in the media store.
    ///
    /// # Arguments
    ///
    /// * `request` - The `MediaRequest` of the file.
    ///
    /// * `content` - The content of the file.
    async fn add_media_content(
        &self,
        request: &MediaRequest,
        content: Vec<u8>,
    ) -> Result<(), Self::Error>;

    /// Get a media file's content out of the media store.
    ///
    /// # Arguments
    ///
    /// * `request` - The `MediaRequest` of the file.
    async fn get_media_content(
        &self,
        request: &MediaRequest,
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Removes a media file's content from the media store.
    ///
    /// # Arguments
    ///
    /// * `request` - The `MediaRequest` of the file.
    async fn remove_media_content(&self, request: &MediaRequest) -> Result<(), Self::Error>;

    /// Removes all the media files' content associated to an `MxcUri` from the
    /// media store.
    ///
    /// # Arguments
    ///
    /// * `uri` - The `MxcUri` of the media files.
    async fn remove_media_content_for_uri(&self, uri: &MxcUri) -> Result<(), Self::Error>;

    /// Removes a room and all elements associated from the state store.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The `RoomId` of the room to delete.
    async fn remove_room(&self, room_id: &RoomId) -> Result<(), Self::Error>;
}
*/
