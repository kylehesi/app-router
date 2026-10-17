//! The interface through which the engine asks "which adapter should this connection use?".
//! The service knows the details of rules and the adapter list; the engine does not.

use std::net::SocketAddrV4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A connection opened by an app. `app` is always the local end on the TUN address.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub proto: Proto,
    pub app: SocketAddrV4,
    pub dst: SocketAddrV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Leave through the interface with this index.
    Interface(u32),
    /// Reject the connection.
    Block,
}

pub trait Policy: Send + Sync + 'static {
    /// May make blocking calls (process table etc.); the engine calls it on a
    /// separate thread.
    fn route(&self, flow: &Flow) -> Route;
}
