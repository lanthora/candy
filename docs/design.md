# Design

## The Simplest Usage of TUN/TAP

Refer to [simpletun](https://github.com/gregnietsky/simpletun) for the simplest peer-to-peer communication.
Here the two peers are named Client A and client B.

```txt
┌──────────┐  ┌──────────┐
│ Client A ├──┤ Client B │
└──────────┘  └──────────┘
```

## Server Traffic Forwarding

On the basis of peer-to-peer communication, a device is added in the middle for traffic forwarding.
There is no change in the traffic sent and received by the two clients.

```txt
┌──────────┐  ┌────────┐  ┌──────────┐
│ Client A ├──┤ Server ├──┤ Client B │
└──────────┘  └────────┘  └──────────┘
```

## Server Traffic Routing

On the basis of forwarding, the Server analyzes the IP data packets uploaded by the Client.
Routing is performed according to the destination address, and the clients can communicate with each other

```txt
┌──────────┐   ┌────────┐   ┌──────────┐
│ Client A ├───┤ Server ├───┤ Client B │
└──────────┘   └───┬────┘   └──────────┘
                   │
              ┌────┴─────┐
              │ Client C │
              └──────────┘
```

## Access Server via VPN

Deploy Client D on the physical machine where the Server is located. This Client is no different from other Clients.
At this point, all devices can communicate with each other.

```txt
              ┌──────────┐
              │ Client D │
              └────┬─────┘
                   │
┌──────────┐   ┌───┴────┐   ┌──────────┐
│ Client A ├───┤ Server ├───┤ Client B │
└──────────┘   └───┬────┘   └──────────┘
                   │
              ┌────┴─────┐
              │ Client C │
              └──────────┘
```

## Network Traffic between Devices

For some well-known reasons, TLS + WebSocket is used for communication.
