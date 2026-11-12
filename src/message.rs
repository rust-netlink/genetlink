// SPDX-License-Identifier: MIT

//! Raw generic netlink payload message
//!
//! # Design
//! Since we use generic type to represent different generic family's message
//! type, and it is not easy to create a underlying
//! [`netlink_proto::new_connection()`] with trait object to multiplex different
//! generic netlink family's message.
//!
//! Therefore, I decided to serialize the generic type payload into bytes before
//! sending to the underlying connection. The [`RawGenlMessage`] is meant for
//! this.
//!
//! This special message doesn't use generic type and its payload is `Vec<u8>`.
//! Therefore, its type is easier to use.
//!
//! Another advantage is that it can let users know when the generic netlink
//! payload fails to decode instead of just dropping the messages.
//! (`netlink_proto` would drop messages if they fails to decode.)
//! I think this can help developers debug their deserializing implementation.
use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, NetlinkDeserializable, NetlinkHeader,
    NetlinkMessage, NetlinkMessagePayload, NetlinkPayload,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};
use std::fmt::Debug;

const GENL_HDRLEN: usize = 4;

/// Message type to hold serialized generic netlink payload
///
/// **Note** This message type is not intend to be used by normal users, unless
/// you need to use the `UnboundedReceiver<(NetlinkMessage<RawGenlMessage>,
/// SocketAddr)>` return by [`new_connection()`](crate::new_connection)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawGenlMessage {
    pub header: GenlHeader,
    pub payload: Vec<u8>,
    pub family_id: u16,
}

impl RawGenlMessage {
    /// Construct the message
    pub fn new(header: GenlHeader, payload: Vec<u8>, family_id: u16) -> Self {
        Self {
            header,
            payload,
            family_id,
        }
    }

    /// Consume this message and return its header and payload
    pub fn into_parts(self) -> (GenlHeader, Vec<u8>) {
        (self.header, self.payload)
    }

    /// Serialize the generic netlink payload into raw bytes
    pub fn from_genlmsg<F>(
        mut genlmsg: GenlMessage<F>,
    ) -> Result<Self, EncodeError>
    where
        F: GenlFamily + Emitable + Debug,
    {
        // Make sure the generic header carries the command and version
        // advertised by the payload instead of whatever the caller left in
        // `GenlMessage::header`.
        genlmsg.finalize();
        let header = genlmsg.header;
        let family_id = genlmsg.family_id();
        let mut payload = Vec::new();
        genlmsg.payload.emit(&mut payload)?;

        Ok(Self {
            header,
            payload,
            family_id,
        })
    }

    /// Try to deserialize the generic netlink payload from raw bytes
    pub fn parse_into_genlmsg<F>(&self) -> Result<GenlMessage<F>, DecodeError>
    where
        F: GenlFamily + ParseableParametrized<[u8], GenlHeader> + Debug,
    {
        let inner = F::parse_with_param(&self.payload, self.header)?;
        Ok(GenlMessage::new(self.header, inner, self.family_id))
    }
}

impl Emitable for RawGenlMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl ParseableParametrized<[u8], u16> for RawGenlMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header = GenlHeader::parse(buf)?;
        let payload_buf = &buf[GENL_HDRLEN..];
        Ok(RawGenlMessage::new(
            header,
            payload_buf.to_vec(),
            message_type,
        ))
    }
}

impl NetlinkMessagePayload for RawGenlMessage {
    fn message_type(&self) -> u16 {
        self.family_id
    }
}

impl NetlinkDeserializable for RawGenlMessage {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        RawGenlMessage::parse_with_param(payload, header.message_type)
    }
}

impl From<RawGenlMessage> for NetlinkPayload<RawGenlMessage> {
    fn from(message: RawGenlMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

/// Helper function to map the [`NetlinkPayload`] types in [`NetlinkMessage`]
/// and serialize the generic netlink payload into raw bytes.
pub fn map_to_rawgenlmsg<F>(
    message: NetlinkMessage<GenlMessage<F>>,
) -> Result<NetlinkMessage<RawGenlMessage>, EncodeError>
where
    F: GenlFamily + Emitable + Debug,
{
    let raw_payload = match message.payload {
        NetlinkPayload::InnerMessage(genlmsg) => {
            NetlinkPayload::InnerMessage(RawGenlMessage::from_genlmsg(genlmsg)?)
        }
        NetlinkPayload::Done(i) => NetlinkPayload::Done(i),
        NetlinkPayload::Error(i) => NetlinkPayload::Error(i),
        NetlinkPayload::Noop => NetlinkPayload::Noop,
        NetlinkPayload::Overrun(i) => NetlinkPayload::Overrun(i),
        i => {
            log::warn!(
                "map_from_rawgenlmsg(): Unexpected NetlinkPayload {:?}",
                i
            );
            NetlinkPayload::Noop
        }
    };
    Ok(NetlinkMessage::new(message.header, raw_payload))
}

/// Helper function to map the [`NetlinkPayload`] types in [`NetlinkMessage`]
/// and try to deserialize the generic netlink payload from raw bytes.
pub fn map_from_rawgenlmsg<F>(
    raw_msg: NetlinkMessage<RawGenlMessage>,
) -> Result<NetlinkMessage<GenlMessage<F>>, DecodeError>
where
    F: GenlFamily + ParseableParametrized<[u8], GenlHeader> + Debug,
{
    let payload = match raw_msg.payload {
        NetlinkPayload::InnerMessage(raw_genlmsg) => {
            NetlinkPayload::InnerMessage(raw_genlmsg.parse_into_genlmsg()?)
        }
        NetlinkPayload::Done(i) => NetlinkPayload::Done(i),
        NetlinkPayload::Error(i) => NetlinkPayload::Error(i),
        NetlinkPayload::Noop => NetlinkPayload::Noop,
        NetlinkPayload::Overrun(i) => NetlinkPayload::Overrun(i),
        i => {
            log::warn!(
                "map_from_rawgenlmsg(): Unexpected NetlinkPayload {:?}",
                i
            );
            NetlinkPayload::Noop
        }
    };
    Ok(NetlinkMessage::new(raw_msg.header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{append_u32, parse_u32, NLM_F_REQUEST};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestPayload {
        cmd: u8,
        version: u8,
        value: u32,
    }

    impl GenlFamily for TestPayload {
        fn family_name() -> &'static str {
            "test"
        }

        fn command(&self) -> u8 {
            self.cmd
        }

        fn version(&self) -> u8 {
            self.version
        }
    }

    impl Emitable for TestPayload {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            append_u32(out, self.value);
            Ok(())
        }
    }

    impl ParseableParametrized<[u8], GenlHeader> for TestPayload {
        fn parse_with_param(
            buf: &[u8],
            header: GenlHeader,
        ) -> Result<Self, DecodeError> {
            Ok(Self {
                cmd: header.cmd,
                version: header.version,
                value: parse_u32(buf)?,
            })
        }
    }

    fn test_message() -> GenlMessage<TestPayload> {
        GenlMessage::from_payload(TestPayload {
            cmd: 9,
            version: 2,
            value: 0x1234,
        })
    }

    #[test]
    fn from_genlmsg_finalizes_header() {
        let mut message = test_message();
        message.header = GenlHeader { cmd: 0, version: 0 };
        message.set_resolved_family_id(42);

        let raw = RawGenlMessage::from_genlmsg(message).unwrap();
        assert_eq!(raw.header, GenlHeader { cmd: 9, version: 2 });
        assert_eq!(raw.family_id, 42);
    }

    #[test]
    fn raw_message_round_trip() {
        let message = test_message();
        let raw = RawGenlMessage::from_genlmsg(message.clone()).unwrap();

        let mut buf = Vec::new();
        raw.emit(&mut buf).unwrap();
        let parsed = RawGenlMessage::parse_with_param(&buf, raw.family_id)
            .expect("failed to parse raw message");
        assert_eq!(parsed, raw);

        let genlmsg = parsed.parse_into_genlmsg::<TestPayload>().unwrap();
        assert_eq!(genlmsg.header, message.header);
        assert_eq!(genlmsg.payload, message.payload);
    }

    #[test]
    fn netlink_message_round_trip() {
        let message = test_message();
        let mut netlink_message = NetlinkMessage::from(message.clone());
        netlink_message.header.flags = NLM_F_REQUEST;

        let outgoing = map_to_rawgenlmsg(netlink_message).unwrap();
        let mut buf = Vec::new();
        outgoing.emit(&mut buf).unwrap();

        let parsed_raw =
            NetlinkMessage::<RawGenlMessage>::deserialize(&buf).unwrap();
        let parsed = map_from_rawgenlmsg::<TestPayload>(parsed_raw).unwrap();
        match parsed.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                assert_eq!(genlmsg.payload, message.payload);
            }
            payload => panic!("unexpected payload: {:?}", payload),
        }
    }
}
