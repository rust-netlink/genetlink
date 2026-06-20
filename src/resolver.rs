// SPDX-License-Identifier: MIT

use crate::{error::GenetlinkError, GenetlinkHandle};
use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
        GenlCtrl, GenlCtrlCmd,
    },
    GenlMessage,
};
use std::{collections::HashMap, future::Future};

/// A [`Resolver`] can resolve information (ID, mutlicast groups) about Netlink
/// family
///
/// It caches the request for future reuse.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    cache: HashMap<&'static str, Family>,
}

/// Metadata about a Generic Netlink family
///
/// A named kernel interface that maps to a numeric family ID and defines its
/// multicast groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Family {
    /// The name of the family
    pub name: String,
    /// The corresponding ID of the family
    pub id: u16,
    /// The multicast groups associated with the family
    /// where key is the name of the group and the value is the ID of the group
    pub multicast_groups: HashMap<String, u32>,
}

impl Resolver {
    /// Create a new empty resolver
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Get the queried family from the cache if available
    pub fn cached_family(&self, family_name: &str) -> Option<Family> {
        self.cache.get(family_name).cloned()
    }

    /// Queries information about the `family_name`.
    /// Returns the internal ID and multicast groups
    /// for the family
    pub async fn query_family(
        &mut self,
        handle: &GenetlinkHandle,
        family_name: &'static str,
    ) -> Result<Family, GenetlinkError> {
        if let Some(family) = self.cache.get(family_name) {
            return Ok(family.clone());
        }

        let mut handle = handle.clone();
        {
            let mut genlmsg: GenlMessage<GenlCtrl> =
                GenlMessage::from_payload(GenlCtrl {
                    cmd: GenlCtrlCmd::GetFamily,
                    nlas: vec![GenlCtrlAttrs::FamilyName(
                        family_name.to_owned(),
                    )],
                });
            genlmsg.finalize();
            // We don't have to set family id here, since nlctrl has static
            // family id (0x10)
            let mut nlmsg = NetlinkMessage::from(genlmsg);
            nlmsg.header.flags = NLM_F_REQUEST;
            nlmsg.finalize();

            let mut res = handle.send_request(nlmsg)?;

            while let Some(result) = res.next().await {
                let rx_packet = result?;
                match rx_packet.payload {
                    NetlinkPayload::InnerMessage(genlmsg) => {
                        // Get the family_id from the first message
                        if !self.cache.contains_key(family_name) {
                            let family_id = genlmsg
                                .payload
                                .nlas
                                .iter()
                                .find_map(|nla| {
                                    if let GenlCtrlAttrs::FamilyId(id) = nla {
                                        Some(*id)
                                    } else {
                                        None
                                    }
                                })
                                .ok_or_else(|| {
                                    GenetlinkError::AttributeNotFound(
                                        "CTRL_ATTR_FAMILY_ID".to_owned(),
                                    )
                                })?;

                            self.cache.insert(
                                family_name,
                                Family {
                                    id: family_id,
                                    name: family_name.to_owned(),
                                    multicast_groups: HashMap::new(),
                                },
                            );
                        }

                        // One specific family name was requested, it can be
                        // assumed, that the mcast groups are part of that
                        // family.
                        let Some(mcast_groups) = genlmsg
                            .payload
                            .nlas
                            .into_iter()
                            .filter_map(|attr| match attr {
                                GenlCtrlAttrs::McastGroups(groups) => {
                                    Some(groups)
                                }
                                _ => None,
                            })
                            .next()
                        else {
                            continue;
                        };

                        for (group_name, group_id) in mcast_groups.into_iter().filter_map(|attrs| {
                                match attrs.as_slice() {
                                    [McastGrpAttrs::Name(name), McastGrpAttrs::Id(i)] |
                                    [McastGrpAttrs::Id(i), McastGrpAttrs::Name(name)] => Some((name.clone(), *i)),
                                    _ => None
                                }
                            }) {
                                self.cache.get_mut(family_name)
                                // the family_id should've been inserted before, but throw and
                                // error just to be sure
                                .ok_or_else(|| {
                                    GenetlinkError::AttributeNotFound(
                                        "CTRL_ATTR_FAMILY_ID".to_owned(),
                                    )
                                })?.multicast_groups.insert(group_name, group_id);
                            }
                    }
                    NetlinkPayload::Error(e) => return Err(e.into()),
                    _ => (),
                }
            }

            Ok(self
                .cache
                .get(family_name)
                .ok_or(GenetlinkError::NoMessageReceived)?
                .clone())
        }
    }

    #[deprecated(note = "use `get` instead")]
    pub fn get_cache_by_name(&self, family_name: &str) -> Option<u16> {
        self.cache.get(family_name).map(|f| f.id)
    }

    #[deprecated(note = "use `cached_family` instead")]
    pub fn query_family_id(
        &mut self,
        handle: &GenetlinkHandle,
        family_name: &'static str,
    ) -> impl Future<Output = Result<u16, GenetlinkError>> + '_ {
        let handle = handle.clone();
        async move { Ok(self.query_family(&handle, family_name).await?.id) }
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[cfg(all(test, feature = "tokio_socket"))]
mod test {
    use super::*;
    use crate::new_connection;
    use std::io::ErrorKind;

    #[tokio::test]
    async fn test_resolver_nlctrl() {
        let (conn, handle, _) = new_connection().unwrap();
        tokio::spawn(conn);

        let mut resolver = Resolver::new();
        let family = resolver.query_family(&handle, "nlctrl").await.unwrap();
        // nlctrl should always be 0x10
        assert_eq!(family.id, 0x10);
    }

    const TEST_FAMILIES: &[&str] = &[
        "devlink",
        "ethtool",
        "acpi_event",
        "tcp_metrics",
        "TASKSTATS",
        "nl80211",
    ];

    #[tokio::test]
    async fn test_resolver_cache() {
        let (conn, handle, _) = new_connection().unwrap();
        tokio::spawn(conn);

        let mut resolver = Resolver::new();

        // Test if family id cached
        for name in TEST_FAMILIES.iter().copied() {
            let family = match resolver.query_family(&handle, name).await {
                Ok(family) => family,
                Err(e) => {
                    if let GenetlinkError::NetlinkError(io_err) = &e {
                        if io_err.kind() == ErrorKind::NotFound {
                            continue;
                        }
                    }
                    panic!("{}", e)
                }
            };
            dbg!(&family);

            let cache = resolver.cached_family(name).unwrap();
            assert_eq!(family, cache);
        }
    }
}
