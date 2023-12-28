Share a Passwd file via a CRDT, securely over Matrix encrypted rooms.

## Creating a new password file

TODO: figure out where to best store the room information. The header is
precarious, due to conflicts and no official extension. My best reasoning at
the moment is to use a password entry with a specially chosen UUID, then
serialize all the descriptor into the comment section as JSON (UTF-8).

## Joining a password file on a new device

TODO: figure out how to send a room invite, mostly. Also, we would like the
user to choose the storage and password method for their persistent file
independently. The program should thus be _given_ a passwd file to work on, not
necessarily create one itself. See also the special entry in creation.

## Security

There are two main security critical portions to this program:

- The communication over the Matrix protocol between devices. The E2E
  implementation takes care of most but we must take care mainly to only invite
  devices we intend to share our password file with. Note that for instance the
  room history setting (`m.room.history_visibility` should be at most `shared`)
  does affect secrecy after device compromise. This will require further
  investigation, i.e. can our CRDT handle forgetting the beginning or do we
  re-start from scratch at some point.

  Our client must also handle the authentication and on-device persistence
  options to securely handle the Matrix device data.

- The on-disk data, which will appear like a [Passwd-file] and more particular
  [the V3 format][Passwd-V3-Format]. Not V4, which adds multiple identities,
  but compromises on compromise recovery.

[Passwd-file]: https://github.com/pwsafe/pwsafe
[Passwd-V3-Format]: https://github.com/pwsafe/pwsafe/blob/80cf00c5812ca96c813d0d24f592ff110cc8cf25/docs/formatV3.txt
