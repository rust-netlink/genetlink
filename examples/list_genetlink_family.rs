// SPDX-License-Identifier: MIT

//! Example of listing generic families based on `netlink_proto`
//!
//! This example's functionality is same as the identical name example in
//! `netlink_packet_generic`. But this example shows you the usage of this crate
//! to run generic netlink protocol asynchronously.

use anyhow::{bail, Error};
use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    GenlCtrlAttr, GenlCtrlCmd, GenlCtrlMessage, GenlMessage,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let nlmsg = NetlinkMessage::new(
        nl_hdr,
        GenlMessage::from_payload(GenlCtrlMessage::new(
            GenlCtrlCmd::GetFamily,
            vec![],
        ))
        .into(),
    );
    let (conn, mut handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut responses = handle.request(nlmsg).await?;

    while let Some(result) = responses.next().await {
        let resp = result?;
        match resp.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                if genlmsg.payload.cmd == GenlCtrlCmd::NewFamily {
                    print_entry(genlmsg.payload.nlas);
                }
            }
            NetlinkPayload::Error(err) => {
                eprintln!("Received a netlink error message: {err:?}");
                bail!(err);
            }
            _ => {}
        }
    }

    Ok(())
}

fn print_entry(entry: Vec<GenlCtrlAttr>) {
    let family_id = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::FamilyId(id) = nla {
                Some(*id)
            } else {
                None
            }
        })
        .expect("Cannot find FamilyId attribute");
    let family_name = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::FamilyName(name) = nla {
                Some(name.as_str())
            } else {
                None
            }
        })
        .expect("Cannot find FamilyName attribute");
    let version = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::Version(ver) = nla {
                Some(*ver)
            } else {
                None
            }
        })
        .expect("Cannot find Version attribute");
    let hdrsize = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::HdrSize(hdr) = nla {
                Some(*hdr)
            } else {
                None
            }
        })
        .expect("Cannot find HdrSize attribute");

    if hdrsize == 0 {
        println!("0x{family_id:04x} {family_name} [Version {version}]");
    } else {
        println!(
            "0x{family_id:04x} {family_name} [Version {version}] \
            [Header {hdrsize} bytes]"
        );
    }
}
