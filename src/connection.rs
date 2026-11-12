// SPDX-License-Identifier: MIT

use crate::{message::RawGenlMessage, GenetlinkHandle};
use futures_channel::mpsc::UnboundedReceiver;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{
    self,
    sys::{protocols::NETLINK_GENERIC, AsyncSocket, SocketAddr},
    Connection,
};
use std::io;

/// Construct a generic netlink connection
///
/// The function would return a tuple containing three objects.
/// - an async netlink connection
/// - a connection handle to interact with the connection
/// - a receiver of the unsolicited messages
///
/// The connection object is also a event loop which implements
/// [`std::future::Future`]. In most cases, users spawn it on an async runtime
/// and use the handle to send messages. For detailed documentation, please
/// refer to [`netlink_proto::new_connection`].
///
/// The [`GenetlinkHandle`] can send and receive any type of generic netlink
/// message. And it can automatic resolve the generic family id before sending.
#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RawGenlMessage>,
    GenetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    new_connection_with_socket()
}

/// Construct a generic netlink connection joined to the given multicast
/// groups.
///
/// The group IDs are the values returned in
/// [`Family::multicast_groups`](crate::resolver::Family::multicast_groups).
/// They must be joined before the connection future is spawned; a separate
/// connection is required to resolve them first.
#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection_with_groups(
    groups: &[u32],
) -> io::Result<(
    Connection<RawGenlMessage>,
    GenetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    new_connection_with_socket_and_groups(groups)
}

/// Variant of [`new_connection`] that allows specifying a socket type to use
/// for async handling
#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    Connection<RawGenlMessage, S>,
    GenetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) =
        netlink_proto::new_connection_with_socket(NETLINK_GENERIC)
            .map_err(proto_error_to_io)?;
    Ok((conn, GenetlinkHandle::new(handle), messages))
}

/// Variant of [`new_connection_with_groups`] that allows specifying a socket
/// type to use for async handling.
#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket_and_groups<S>(
    groups: &[u32],
) -> io::Result<(
    Connection<RawGenlMessage, S>,
    GenetlinkHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (mut conn, handle, messages) = new_connection_with_socket::<S>()?;
    for &group in groups {
        conn.socket_mut().socket_ref().add_membership(group)?;
    }
    Ok((conn, handle, messages))
}

fn proto_error_to_io(err: netlink_proto::NetlinkProtoError) -> io::Error {
    match err {
        netlink_proto::NetlinkProtoError::SocketIo(err) => err,
        err => io::Error::other(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn socket_error_kind_is_preserved() {
        let err =
            proto_error_to_io(netlink_proto::NetlinkProtoError::SocketIo(
                Error::from_raw_os_error(13),
            ));
        assert_eq!(err.raw_os_error(), Some(13));
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn other_errors_are_wrapped() {
        let err = proto_error_to_io(
            netlink_proto::NetlinkProtoError::ConnectionClosed,
        );
        assert_eq!(err.kind(), ErrorKind::Other);
    }
}

#[cfg(all(test, feature = "tokio_socket"))]
mod group_tests {
    use super::*;

    #[tokio::test]
    async fn joins_nlctrl_notify_group() {
        // `nlctrl` is allocated group ID `GENL_ID_CTRL` (16) and exposes
        // its "notify" group there.
        let (conn, _handle, _messages) =
            new_connection_with_groups(&[16]).unwrap();
        drop(conn);
    }
}
