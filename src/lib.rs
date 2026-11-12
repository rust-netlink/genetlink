// SPDX-License-Identifier: MIT

mod connection;
mod error;
mod handle;
pub mod message;
pub mod resolver;

#[cfg(feature = "tokio_socket")]
pub use connection::{new_connection, new_connection_with_groups};
pub use connection::{
    new_connection_with_socket, new_connection_with_socket_and_groups,
};
pub use error::GenetlinkError;
pub use handle::GenetlinkHandle;
