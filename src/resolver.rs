// SPDX-License-Identifier: MIT

use crate::{error::GenetlinkError, GenetlinkHandle};
use futures::{future::Either, StreamExt};
use log::{error, trace, warn};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::{GenlCtrlAttrs, McastGrpAttrs}, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use std::{collections::HashMap, future::Future};

#[derive(Clone, Debug, Default)]
pub struct Resolver {
    cache: HashMap<&'static str, u16>,
    groups_cache: HashMap<&'static str, HashMap<String, u32>>
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            groups_cache: HashMap::new(),
        }
    }

    pub fn get_cache_by_name(&self, family_name: &str) -> Option<u16> {
        self.cache.get(family_name).copied()
    }

    pub fn get_groups_cache_by_name(&self, family_name: &str) -> Option<HashMap<String, u32>> {
        self.groups_cache.get(family_name).cloned()
    }

    pub fn query_family_id(
        &mut self,
        handle: &GenetlinkHandle,
        family_name: &'static str,
    ) -> impl Future<Output = Result<u16, GenetlinkError>> + '_ {
        if let Some(id) = self.get_cache_by_name(family_name) {
            Either::Left(futures::future::ready(Ok(id)))
        } else {
            let mut handle = handle.clone();
            Either::Right(async move {
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

                            self.cache.insert(family_name, family_id);
                            return Ok(family_id);
                        }
                        NetlinkPayload::Error(e) => return Err(e.into()),
                        _ => (),
                    }
                }

                Err(GenetlinkError::NoMessageReceived)
            })
        }
    }

    pub fn query_family_multicast_groups(
        &mut self,
        handle: &GenetlinkHandle,
        family_name: &'static str,
    ) -> impl Future<Output = Result<HashMap<String, u32>, GenetlinkError>> + '_ {
        let mut handle = handle.clone();
        async move {
            trace!("Starting query_family_multicast_groups for family_name: '{}'", family_name);
    
            // First, get the family ID (this uses your existing method)
            trace!("Calling query_family_id for family_name: '{}'", family_name);
            let family_id = self.query_family_id(&handle, family_name).await?;
            trace!("Received family_id: {}", family_id);
    
            // Create the request message to get family details
            trace!("Creating GenlMessage for CTRL_CMD_GETFAMILY");
            let mut genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
                cmd: GenlCtrlCmd::GetFamily,
                nlas: vec![GenlCtrlAttrs::FamilyId(family_id)],
            });
            genlmsg.finalize();
            let mut nlmsg = NetlinkMessage::from(genlmsg);
            nlmsg.header.flags = NLM_F_REQUEST;
            nlmsg.finalize();
            trace!("NetlinkMessage created: {:?}", nlmsg);
    
            // Send the request
            trace!("Sending NetlinkMessage to netlink socket");
            let mut res = handle.send_request(nlmsg)?;
            trace!("Request sent, awaiting response");
    
            // Prepare to collect multicast groups
            let mut mc_groups = HashMap::new();
    
            // Process the response
            trace!("Processing responses");
            while let Some(result) = res.next().await {
                trace!("Received a response");
                let rx_packet = result?;
                trace!("Received NetlinkMessage: {:?}", rx_packet);
                match rx_packet.payload {
                    NetlinkPayload::InnerMessage(genlmsg) => {
                        trace!("Processing InnerMessage: {:?}", genlmsg);
                        for nla in genlmsg.payload.nlas {
                            trace!("Processing NLA: {:?}", nla);
                            if let GenlCtrlAttrs::McastGroups(groups) = nla {
                                trace!("Found McastGroups: {:?}", groups);
                                for group in groups {
                                    // 'group' is a Vec<McastGrpAttrs>
                                    let mut group_name = None;
                                    let mut group_id = None;
    
                                    for group_attr in group {
                                        trace!("Processing group_attr: {:?}", group_attr);
                                        match group_attr {
                                            McastGrpAttrs::Name(ref name) => {
                                                group_name = Some(name.clone());
                                                trace!("Found group name: '{}'", name);
                                            }
                                            McastGrpAttrs::Id(id) => {
                                                group_id = Some(id);
                                                trace!("Found group id: {}", id);
                                            }
                                        }
                                    }
    
                                    if let (Some(name), Some(id)) = (group_name, group_id) {
                                        mc_groups.insert(name.clone(), id);
                                        trace!(
                                            "Inserted group '{}' with id {} into mc_groups",
                                            name,
                                            id
                                        );
                                    }
                                }
                            } else {
                                trace!("Unhandled NLA: {:?}", nla);
                            }
                        }
                    }
                    NetlinkPayload::Error(e) => {
                        error!("Received NetlinkPayload::Error: {:?}", e);
                        return Err(e.into());
                    }
                    other => {
                        warn!("Received unexpected NetlinkPayload: {:?}", other);
                    }
                }
            }
            trace!("Finished processing responses");
    
            // Update the cache
            self.groups_cache.insert(family_name, mc_groups.clone());
            trace!("Updated groups_cache for family_name: '{}'", family_name);
    
            trace!("Returning mc_groups: {:?}", mc_groups);
            Ok(mc_groups)
        }
    }
    

    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.groups_cache.clear();
    }

}

#[cfg(all(test, tokio_socket))]
mod test {
    use super::*;
    use crate::new_connection;
    use std::io::ErrorKind;

    #[tokio::test]
    async fn test_resolver_nlctrl() {
        let (conn, handle, _) = new_connection().unwrap();
        tokio::spawn(conn);

        let mut resolver = Resolver::new();
        // nlctrl should always be 0x10
        let nlctrl_fid =
            resolver.query_family_id(&handle, "nlctrl").await.unwrap();
        assert_eq!(nlctrl_fid, 0x10);
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
            let id = resolver
                .query_family_id(&handle, name)
                .await
                .or_else(|e| {
                    if let GenetlinkError::NetlinkError(io_err) = &e {
                        if io_err.kind() == ErrorKind::NotFound {
                            // Ignore non exist entries
                            Ok(0)
                        } else {
                            Err(e)
                        }
                    } else {
                        Err(e)
                    }
                })
                .unwrap();
            if id == 0 {
                log::warn!(
                    "Generic family \"{name}\" not exist or not loaded \
                    in this environment. Ignored."
                );
                continue;
            }

            let cache = resolver.get_cache_by_name(name).unwrap();
            assert_eq!(id, cache);
            log::warn!("{:?}", (name, cache));
        }
    }
}
