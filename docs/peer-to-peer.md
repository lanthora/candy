# Peer to Peer

- [Index](index.md)
- [Specification](specification.md)
- [Forward](forward.md)
- Peer to Peer

## State Machine

### INIT

When receiving an IPv4 packet forwarded by the server, check whether the source address is in the INIT state. If yes, enter the PREPARING state. If the peer-to-peer connection feature is not enabled, switch to the FAILED state. Ignore other states.

### PREPARING

Tick checks whether there are any peers in the PREPARING state. If there are, it sends a STUN request after traversing all the peers. When receiving a STUN response, it sends its public network information to all the peers in the PREPARING state. If it does not have the public network information of the other peer, the state will be switched to SYNCHRONIZING, otherwise it will be switched to CONNECTING. STUN is UDP, which may lose packets, so it keeps sending STUN requests as long as there are peers in the PREPARING state.

### SYNCHRONIZING

This state means that it has sent its public network information to the other peer, but has not received the public network information of the other peer. At this time, the other peer may be sending, or the other peer’s version does not support, or the other peer’s version supports but does not enable peer-to-peer connection. After timeout, it enters FAILED.

### CONNECTING

This state means that it has the public network information of the other peer, and has sent its public network information to the other peer. It means that both peers have enabled the peer-to-peer connection feature, and start sending UDP heartbeats to try to establish a connection. After the connection is successful, it enters CONNECTED. After timeout, it enters WAITTING.

### CONNECTED

When TUN receives data, if the peer is in the CONNECTED state, it directly sends it via UDP. Tick sends heartbeats to the peer, and checks whether it has received the peer’s heartbeats recently. If not, it enters the INIT state. When UDP receives the peer’s heartbeats, it updates the state and records that it has received the heartbeats recently.

### WAITTING

Using the exponential backoff algorithm, it re-enters the INIT state after a specific time. The retry interval ranges from 30 seconds to 1 hour, and eventually stays at 1 hour retry.

### FAILED

The FAILED state means that the peer does not support peer-to-peer connection at all, and no active measures are taken for the peer in this state. But if it receives the connection message from the peer, it will passively enter the PREPARING state. This corresponds to the situation where the peer switches from a client that does not support peer-to-peer connection to a client that supports peer-to-peer connection.
