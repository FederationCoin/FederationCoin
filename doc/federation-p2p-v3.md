# FCN-P2P-v3

Launch transport is BIP324 (**v2**): 3-byte length, one message per packet,
`MAX_CONTENTS_LEN` = 2^24 − 1 (~16 MiB). **v1** (`V1Transport`) is the
unencrypted handshake downgrade only. It is not the grow path.

**v3** is dormant until live admit cannot fit in one v2 packet
(`V2CanCarryAdmitCap()` is false). The trigger is live admit, not
`MAX_FLEX_BLOCK_WEIGHT`. Until that crossing, this node speaks v2.

## Handshake

Ellswift keys, garbage, garbage terminator, ignore bit `0x80`, and rekey
stay BIP324. Version and application packets before v3 is selected still
use the 3-byte length.

Version packet contents:

- empty: this side will speak v2 application packets
- first byte `0x03`: this side offers v3 application packets

This node sends `0x03` only when `V2CanCarryAdmitCap()` is false. It
selects v3 application framing only when **both** sides offered `0x03`.
If this side needs v3 and the peer sent empty, the connection drops.
A peer that offers `0x03` while this side can still carry v2 is ignored;
application packets stay v2.

Already-open v2 sessions at the crossing are disconnected so the next
handshake can offer `0x03`. The same rebuild runs during IBD.

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
ordered.

First non-ignore frame contents:

- BIP324 message-type encoding (short id, or `0x00` plus 12-byte type)
- 8-byte little-endian `total_payload`
- payload bytes

Later non-ignore frames are payload only. The last frame clears `MORE`.
`total_payload` greater than `CommandReceiveLimit(type)` disconnects.
Assembled bytes other than `total_payload` when `MORE` is clear
disconnect. `MORE` set after `total_payload` bytes are already assembled
disconnects.

## Service bit

`NODE_P2P_V2` is advertised while v2 can still carry admit. After the
crossing, `GetLocalServices()` advertises `NODE_P2P_V3` instead. Outbound
encrypted handshake is offered when either bit is set locally and the
peer advertised either bit.
