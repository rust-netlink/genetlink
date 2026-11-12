// SPDX-License-Identifier: MIT

use std::fmt;

/// Error type of genetlink
#[derive(Debug)]
pub enum GenetlinkError {
    ProtocolError(netlink_proto::NetlinkProtoError),
    DecodeError(netlink_packet_core::DecodeError),
    EncodeError(netlink_packet_core::EncodeError),
    NetlinkError(std::io::Error),
    AttributeNotFound(String),
    NoMessageReceived,
}

impl fmt::Display for GenetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenetlinkError::ProtocolError(_) => {
                write!(f, "Failed to send netlink request")
            }
            GenetlinkError::DecodeError(_) => {
                write!(f, "Failed to decode generic packet")
            }
            GenetlinkError::EncodeError(_) => {
                write!(f, "Failed to encode generic packet")
            }
            GenetlinkError::NetlinkError(err) => {
                write!(f, "Netlink error message: {}", err)
            }
            GenetlinkError::AttributeNotFound(attr) => {
                write!(f, "Cannot find specified netlink attribute: {}", attr)
            }
            GenetlinkError::NoMessageReceived => {
                write!(f, "Desire netlink message type not received")
            }
        }
    }
}

impl std::error::Error for GenetlinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GenetlinkError::ProtocolError(err) => Some(err),
            GenetlinkError::DecodeError(err) => Some(err),
            GenetlinkError::EncodeError(err) => Some(err),
            GenetlinkError::NetlinkError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<netlink_proto::NetlinkProtoError> for GenetlinkError {
    fn from(err: netlink_proto::NetlinkProtoError) -> Self {
        Self::ProtocolError(err)
    }
}

impl From<netlink_packet_core::DecodeError> for GenetlinkError {
    fn from(err: netlink_packet_core::DecodeError) -> Self {
        Self::DecodeError(err)
    }
}

impl From<netlink_packet_core::EncodeError> for GenetlinkError {
    fn from(err: netlink_packet_core::EncodeError) -> Self {
        Self::EncodeError(err)
    }
}

// Since `netlink_packet_core::error::ErrorMessage` doesn't impl `Error` trait,
// it need to convert to `std::io::Error` here
impl From<netlink_packet_core::ErrorMessage> for GenetlinkError {
    fn from(err_msg: netlink_packet_core::ErrorMessage) -> Self {
        Self::NetlinkError(err_msg.to_io())
    }
}
