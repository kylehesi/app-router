//! Routing engine.
//!
//! ```text
//! app --> Wintun TUN (0.0.0.0/1 + 128.0.0.0/1 + 2000::/3) --> tun-reader thread
//!                                                               |
//!   TCP:  "system stack" NAT. Packets are rewritten in place and handed to a
//!         local listener on Windows' own TCP stack; Windows terminates TCP.
//!   UDP:  one session per app port.
//!   IPv6: TCP is rejected with RST so apps fall back to IPv4.
//!                                                               |
//!   Policy::route(flow) -> which adapter? (service: socket -> PID -> exe -> rule)
//!                                                               |
//!   outbound socket: bind::connect_tcp / bind::bind_udp (IP_UNICAST_IF)
//!                    -> chosen physical adapter. These sockets never loop back into the TUN.
//! ```

pub mod bind;
pub mod checksum;
pub mod flows;
pub mod nat;
pub mod packet;
pub mod policy;
mod stack;
pub mod tun;

pub use policy::{Flow, Policy, Proto, Route};
pub use stack::{
    Engine, EngineConfig, FULL_TUNNEL, PEER_IP, TUN_IP, TUN_IP6, TUN_MTU, TUN_PREFIX_LEN,
};
