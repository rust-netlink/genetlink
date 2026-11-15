// SPDX-License-Identifier: MIT

use std::fmt;

/// Error type of genetlink
#[derive(Debug)]
#[non_exhaustive]
pub enum GenetlinkError {
    ProtocolError(netlink_proto::NetlinkProtoError),
    DecodeError(netlink_packet_core::DecodeError),
    EncodeError(netlink_packet_core::EncodeError),
    NetlinkError(netlink_packet_core::ErrorMessage),
    AttributeNotFound(String),
    NoMessageReceived,
}

impl fmt::Display for GenetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenetlinkError::ProtocolError(err) => {
                write!(f, "Netlink protocol error: {}", err)
            }
            GenetlinkError::DecodeError(err) => {
                write!(f, "Failed to decode generic packet: {}", err)
            }
            GenetlinkError::EncodeError(err) => {
                write!(f, "Failed to encode generic packet: {}", err)
            }
            GenetlinkError::NetlinkError(err) => {
                write!(f, "Netlink error message: {}", err)
            }
            GenetlinkError::AttributeNotFound(attr) => {
                write!(f, "Cannot find specified netlink attribute: {}", attr)
            }
            GenetlinkError::NoMessageReceived => {
                write!(f, "Desired netlink message type not received")
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

impl From<std::io::Error> for GenetlinkError {
    fn from(err: std::io::Error) -> Self {
        Self::ProtocolError(netlink_proto::NetlinkProtoError::SocketIo(err))
    }
}

// `netlink_packet_core::ErrorMessage` does not implement the `Error` trait,
// so it is stored as-is to keep the errno and original request header.
impl From<netlink_packet_core::ErrorMessage> for GenetlinkError {
    fn from(err_msg: netlink_packet_core::ErrorMessage) -> Self {
        Self::NetlinkError(err_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::ErrorMessage;
    use std::num::NonZeroI32;

    #[test]
    fn netlink_error_preserves_details() {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-2);
        error.header = vec![1, 2, 3];

        let error: GenetlinkError = error.into();
        match error {
            GenetlinkError::NetlinkError(error) => {
                assert_eq!(error.raw_code(), -2);
                assert_eq!(error.header, vec![1, 2, 3]);
            }
            error => panic!("unexpected error: {:?}", error),
        }
    }

    #[test]
    fn io_error_is_wrapped_as_socket_io() {
        let error: GenetlinkError =
            std::io::Error::from_raw_os_error(13).into();
        match error {
            GenetlinkError::ProtocolError(
                netlink_proto::NetlinkProtoError::SocketIo(error),
            ) => {
                assert_eq!(error.raw_os_error(), Some(13));
            }
            error => panic!("unexpected error: {:?}", error),
        }
    }

    #[test]
    fn no_message_received_display() {
        assert_eq!(
            GenetlinkError::NoMessageReceived.to_string(),
            "Desired netlink message type not received"
        );
    }
}
