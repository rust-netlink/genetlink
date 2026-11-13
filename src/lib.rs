// SPDX-License-Identifier: MIT

mod connection;
mod error;
mod handle;
mod message;
mod resolver;

#[cfg(feature = "tokio_socket")]
pub use self::connection::{new_connection, new_connection_with_group_names};
pub use self::connection::{
    new_connection_with_socket, new_connection_with_socket_and_group_names,
    new_connection_with_socket_and_groups, GenlProtocolFamily,
};
pub use self::error::GenetlinkError;
pub use self::handle::GenetlinkHandle;
pub use self::message::RawGenlMessage;
