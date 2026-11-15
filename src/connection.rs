// SPDX-License-Identifier: MIT

use crate::{
    resolver::Resolver, GenetlinkError, GenetlinkHandle, RawGenlMessage,
};
use futures_channel::mpsc::UnboundedReceiver;
use futures_util::future::{select, Either};
use netlink_packet_core::NetlinkMessage;
use netlink_proto::{
    self,
    sys::{AsyncSocket, SocketAddr},
    Connection,
};

const NETLINK_GENERIC: isize = libc::NETLINK_GENERIC as isize;

/// A generic netlink family and one of its multicast groups.
///
/// This is used by `new_connection_with_group_names()` to resolve multicast
/// group IDs by name.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GenlProtocolFamily {
    family_name: String,
    group_name: String,
}

impl GenlProtocolFamily {
    /// Create a family/group pair from the generic netlink family name and
    /// multicast group name.
    pub fn new(
        family_name: impl Into<String>,
        group_name: impl Into<String>,
    ) -> Self {
        Self {
            family_name: family_name.into(),
            group_name: group_name.into(),
        }
    }

    /// The generic netlink family name.
    pub fn family_name(&self) -> &str {
        &self.family_name
    }

    /// The multicast group name within the family.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }
}

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
pub fn new_connection() -> Result<
    (
        Connection<RawGenlMessage>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
> {
    new_connection_with_socket()
}

/// Construct a generic netlink connection joined to the given multicast
/// groups, identified by family and group name.
///
/// The multicast group IDs are resolved through the kernel's `nlctrl` family
/// before the connection is created. The groups must be joined before the
/// connection future is spawned.
#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub async fn new_connection_with_group_names(
    groups: &[GenlProtocolFamily],
) -> Result<
    (
        Connection<RawGenlMessage>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
> {
    let group_ids =
        resolve_multicast_group_ids::<netlink_proto::sys::TokioSocket>(groups)
            .await?;
    new_connection_with_groups(&group_ids)
}

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub(crate) fn new_connection_with_groups(
    groups: &[u32],
) -> Result<
    (
        Connection<RawGenlMessage>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
> {
    new_connection_with_socket_and_groups(groups)
}

/// Variant of [`new_connection`] that allows specifying a socket type to use
/// for async handling
#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> Result<
    (
        Connection<RawGenlMessage, S>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) =
        netlink_proto::new_connection_with_socket(NETLINK_GENERIC)?;
    Ok((conn, GenetlinkHandle::new(handle), messages))
}

/// Variant of [`new_connection_with_group_names()`] that allows specifying a
/// socket type to use for async handling.
#[allow(clippy::type_complexity)]
pub async fn new_connection_with_socket_and_group_names<S>(
    groups: &[GenlProtocolFamily],
) -> Result<
    (
        Connection<RawGenlMessage, S>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
>
where
    S: AsyncSocket,
{
    let group_ids = resolve_multicast_group_ids::<S>(groups).await?;
    new_connection_with_socket_and_groups(&group_ids)
}

/// Low-level variant of [`new_connection_with_group_names()`] that takes
/// already resolved multicast group IDs and allows specifying a socket type
/// to use for async handling.
#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket_and_groups<S>(
    groups: &[u32],
) -> Result<
    (
        Connection<RawGenlMessage, S>,
        GenetlinkHandle,
        UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    ),
    GenetlinkError,
>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) = new_connection_with_socket::<S>()?;
    if !groups.is_empty() {
        // Bind the socket so it gets a nonzero portid. The kernel skips
        // sockets whose portid matches the multicast sender's exclusion
        // portid, and portid-zero multicast would otherwise skip an unbound
        // listener, which also has portid zero.
        conn.socket_ref()
            .socket_ref()
            .bind(&SocketAddr::new(0, 0))?;
    }
    for &group in groups {
        conn.socket_ref().socket_ref().add_membership(group)?;
    }
    Ok((conn, handle, messages))
}

async fn resolve_multicast_group_ids<S>(
    groups: &[GenlProtocolFamily],
) -> Result<Vec<u32>, GenetlinkError>
where
    S: AsyncSocket,
{
    if groups.is_empty() {
        return Ok(Vec::new());
    }

    let (conn, handle, _messages) = new_connection_with_socket::<S>()?;

    let resolve = async {
        let mut resolver = Resolver::new();
        let mut group_ids = Vec::with_capacity(groups.len());
        for group in groups {
            let family =
                resolver.query_family(&handle, group.family_name()).await?;
            let group_id = family
                .multicast_groups
                .get(group.group_name())
                .copied()
                .ok_or_else(|| {
                    GenetlinkError::AttributeNotFound(format!(
                        "multicast group '{}' in family '{}'",
                        group.group_name(),
                        group.family_name()
                    ))
                })?;
            group_ids.push(group_id);
        }
        Ok::<Vec<u32>, GenetlinkError>(group_ids)
    };

    let mut conn = std::pin::pin!(conn);
    let mut resolve = std::pin::pin!(resolve);
    match select(conn.as_mut(), resolve.as_mut()).await {
        Either::Left((result, _)) => match result {
            Ok(()) => Err(GenetlinkError::NoMessageReceived),
            Err(err) => Err(err.into()),
        },
        Either::Right((result, _)) => result,
    }
}

#[cfg(all(test, feature = "tokio_socket"))]
mod group_tests {
    use super::*;

    #[tokio::test]
    async fn joins_nlctrl_notify_group() {
        let (conn, _handle, _messages) =
            new_connection_with_group_names(&[GenlProtocolFamily::new(
                "nlctrl", "notify",
            )])
            .await
            .unwrap();

        let mut addr = SocketAddr::new(0, 0);
        conn.socket_ref()
            .socket_ref()
            .get_address(&mut addr)
            .unwrap();
        assert_ne!(addr.port_number(), 0);

        drop(conn);
    }
}
