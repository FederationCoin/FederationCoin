# FCN-P2P-v3

Encrypted handshake is BIP324. Application framing is **v3 from genesis**.
**v1** (`V1Transport`) is the unencrypted handshake downgrade only.

Do not raise BIP324 `MAX_CONTENTS_LEN` (~16 MiB). Grown and historical
blocks use v3 `MORE` frames. Non-block messages stay at 4,000,000 bytes
(`MAX_PROTOCOL_MESSAGE_LENGTH`). That is not a consensus cap and is not
32 MiB.

Compact-block differential indexes (`PrefilledTransaction::index` and
`BlockTransactionsRequest::indexes`) are **32-bit** from genesis. A
16-bit index would plant a chatter ceiling near 65,535 transactions.
This is our compact dialect, not a later BIP152 raise.

## Handshake

Ellswift keys, garbage, garbage terminator, ignore bit `0x80`, and rekey
stay BIP324. Version and application packets before v3 is selected still
use the 3-byte length.

Version packet contents:

- empty: this side speaks BIP324 v2 application packets
- first byte `0x03`: this side offers v3 application packets

This node always sends `0x03`. It selects v3 application framing when
**both** sides offered `0x03`. An empty peer version stays on v2
application; it is not disconnected later when admit grows. Unencrypted
v1 is only the prefix-detected handshake downgrade.

Already-open v2 application sessions stay. There is no network-wide
disconnect at a predictable height.

## Application packets

Each AEAD frame:

- 8-byte little-endian length = this frame's contents size (not the
  1-byte header)
- header byte: `IGNORE 0x80`, `MORE 0x40`; other bits reserved 0
- contents, then Poly1305 tag

`MAX_AEAD_FRAME` equals BIP324 `MAX_CONTENTS_LEN`. A decrypted length
greater than that disconnects.

`MORE` set means another frame follows for the same message. Ignore
frames do not join the assembly. There is no n-of-m index; TCP is
ordered. Small messages use one frame.

First non-ignore frame contents:

- BIP324 message-type encoding (short id, or `0x00` plus 12-byte type)
- 8-byte little-endian `total_payload`
- payload bytes

Later non-ignore frames are payload only. The last frame clears `MORE`.
`total_payload` greater than `CommandReceiveLimit(type)` disconnects.
Assembled bytes other than `total_payload` when `MORE` is clear
disconnect. `MORE` set after `total_payload` bytes are already assembled
disconnects.

## Admit and send size

Receive and send size for `block` / `cmpctblock` / `blocktxn` is a
property of the **block**, not of our tip.

- Unsolicited chatter uses the tip-window floor
  (`AdmitWeightForWindow` looks **ahead** only).
- Indexed headers raise a receive floor to that header's `nFlexCap`
  (`NoteHeaderFlexCap`). A grow-fork we have not connected still
  arrives.
- v3 send of a served block is never `MessageTooLargeToSend` against
  the live tip. After a shrink, historical larger blocks still send.
  If a requested block still cannot be framed, log and drop that send
  (`notfound` is the inventory miss path); do not stall the socket.

## Service bit

`NODE_P2P_V3` is advertised from genesis whenever encrypted P2P is
offered (`-v2transport=1`). `NODE_P2P_V2` stays advertised while a v2
packet can still name a block at the live receive limit. After that,
`GetLocalServices()` advertises `NODE_P2P_V3` only. Outbound encrypted
handshake is offered when either bit is set locally and the peer
advertised either bit. `-v2transport=0` stays v1.
