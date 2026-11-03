// SPDX-License-Identifier: MIT

mod connection;
mod error;
mod handle;
pub mod message;
pub mod resolver;

#[cfg(feature = "tokio_socket")]
pub use connection::new_connection;
pub use connection::new_connection_with_socket;
pub use error::GenetlinkError;
pub use handle::GenetlinkHandle;
