// SPDX-License-Identifier: MIT

use crate::{error::GenetlinkError, GenetlinkHandle};
use futures_util::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    GenlCtrlAttr, GenlCtrlCmd, GenlCtrlMcastGroup, GenlCtrlMessage,
    GenlCtrlOpSet, GenlMessage,
};
use std::{collections::HashMap, future::Future};

/// A [`Resolver`] can resolve information (ID, mutlicast groups) about Netlink
/// family
///
/// It caches the request for future reuse.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    cache: HashMap<String, Family>,
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
    /// The family protocol version
    pub version: u32,
    /// Length of the family specific header in bytes
    pub hdrsize: u32,
    /// Maximum number of attributes supported by the family
    pub maxattr: u32,
    /// Operations supported by the family
    pub ops: Vec<GenlCtrlOpSet>,
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
        family_name: &str,
    ) -> Result<Family, GenetlinkError> {
        if let Some(family) = self.cache.get(family_name) {
            return Ok(family.clone());
        }

        {
            let genlmsg: GenlMessage<GenlCtrlMessage> =
                GenlMessage::from_payload(GenlCtrlMessage::new(
                    GenlCtrlCmd::GetFamily,
                    vec![GenlCtrlAttr::FamilyName(family_name.to_owned())],
                ));
            // We don't have to set family id here, since nlctrl has static
            // family id (0x10)
            let mut nlmsg = NetlinkMessage::from(genlmsg);
            nlmsg.header.flags = NLM_F_REQUEST;

            let mut res = handle.send_request(nlmsg)?;

            while let Some(result) = res.next().await {
                let rx_packet = result?;
                match rx_packet.payload {
                    NetlinkPayload::InnerMessage(genlmsg) => {
                        self.update_family(family_name, genlmsg.payload.nlas)?;
                    }
                    NetlinkPayload::Error(e) => return Err(e.into()),
                    _ => (),
                }
            }

            self.cached_family(family_name)
                .ok_or(GenetlinkError::NoMessageReceived)
        }
    }

    fn update_family(
        &mut self,
        family_name: &str,
        nlas: Vec<GenlCtrlAttr>,
    ) -> Result<(), GenetlinkError> {
        let mut family =
            self.cache.remove(family_name).unwrap_or_else(|| Family {
                name: family_name.to_owned(),
                ..Default::default()
            });

        for nla in nlas {
            match nla {
                GenlCtrlAttr::FamilyId(id) => family.id = id,
                GenlCtrlAttr::Version(version) => family.version = version,
                GenlCtrlAttr::HdrSize(hdrsize) => family.hdrsize = hdrsize,
                GenlCtrlAttr::MaxAttr(maxattr) => family.maxattr = maxattr,
                GenlCtrlAttr::Ops(ops) => family.ops = ops,
                GenlCtrlAttr::McastGroups(groups) => {
                    for group in groups {
                        let mut group_name = None;
                        let mut group_id = None;
                        for attr in group.attrs {
                            match attr {
                                GenlCtrlMcastGroup::Name(name) => {
                                    group_name = Some(name);
                                }
                                GenlCtrlMcastGroup::Id(id) => {
                                    group_id = Some(id);
                                }
                                _ => {}
                            }
                        }
                        if let (Some(group_name), Some(group_id)) =
                            (group_name, group_id)
                        {
                            family
                                .multicast_groups
                                .insert(group_name, group_id);
                        }
                    }
                }
                _ => {}
            }
        }

        if family.id == 0 {
            return Err(GenetlinkError::AttributeNotFound(
                "CTRL_ATTR_FAMILY_ID".to_owned(),
            ));
        }

        self.cache.insert(family_name.to_owned(), family);
        Ok(())
    }

    #[deprecated(note = "use `cached_family` instead")]
    pub fn get_cache_by_name(&self, family_name: &str) -> Option<u16> {
        self.cache.get(family_name).map(|f| f.id)
    }

    #[deprecated(note = "use `cached_family` instead")]
    pub fn query_family_id<'a>(
        &'a mut self,
        handle: &GenetlinkHandle,
        family_name: &'a str,
    ) -> impl Future<Output = Result<u16, GenetlinkError>> + 'a {
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
        let family_name = String::from("nlctrl");
        let family =
            resolver.query_family(&handle, &family_name).await.unwrap();
        // nlctrl should always be 0x10
        assert_eq!(family.id, 0x10);
        assert_eq!(resolver.cached_family(&family_name), Some(family));
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

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_generic::{
        GenlCtrlMcastGroupSet, GenlCtrlOp, GenlCtrlOpFlags,
    };

    #[test]
    fn update_family_parses_metadata() {
        let mut resolver = Resolver::new();
        resolver
            .update_family(
                "test",
                vec![
                    GenlCtrlAttr::FamilyName("test".to_string()),
                    GenlCtrlAttr::FamilyId(42),
                    GenlCtrlAttr::Version(3),
                    GenlCtrlAttr::HdrSize(8),
                    GenlCtrlAttr::MaxAttr(10),
                    GenlCtrlAttr::Ops(vec![GenlCtrlOpSet::new(
                        1,
                        vec![
                            GenlCtrlOp::Id(1),
                            GenlCtrlOp::Flags(GenlCtrlOpFlags::CmdCapDo),
                        ],
                    )]),
                    GenlCtrlAttr::McastGroups(vec![
                        GenlCtrlMcastGroupSet::new(
                            1,
                            vec![
                                GenlCtrlMcastGroup::Id(100),
                                GenlCtrlMcastGroup::Name("events".to_string()),
                            ],
                        ),
                    ]),
                ],
            )
            .unwrap();

        let family = resolver.cached_family("test").unwrap();
        assert_eq!(family.name, "test");
        assert_eq!(family.id, 42);
        assert_eq!(family.version, 3);
        assert_eq!(family.hdrsize, 8);
        assert_eq!(family.maxattr, 10);
        assert_eq!(family.ops.len(), 1);
        assert_eq!(family.ops[0].index, 1);
        assert_eq!(family.multicast_groups.get("events"), Some(&100u32));
    }

    #[test]
    fn update_family_requires_family_id() {
        let mut resolver = Resolver::new();
        let err = resolver
            .update_family("test", vec![GenlCtrlAttr::Version(3)])
            .unwrap_err();
        assert!(matches!(err, GenetlinkError::AttributeNotFound(_)));
        assert!(resolver.cached_family("test").is_none());
    }
}
