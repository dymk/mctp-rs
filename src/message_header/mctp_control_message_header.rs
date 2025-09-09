use crate::MctpMessageHeader;
use crate::mctp_command_code::MctpCommandCode;
use crate::mctp_completion_code::MctpCompletionCode;
use crate::mctp_message_type::MctpMessageType;
use bit_register::bit_register;

bit_register! {
    /// if message_type is MctpMessageType::MctpControl, then the header is a MctpControlMessageHeader
    /// with message specific fields.
    #[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
    pub struct MctpControlMessageHeader: little_endian u32 {
        pub integrity_check: u8 => [31],
        pub message_type: MctpMessageType => [24:30],
        pub request_bit: u8 => [23],
        pub datagram_bit: u8 => [22],
        pub instance_id: u8 => [16:20],
        pub command_code: MctpCommandCode => [8:15],
        pub completion_code: MctpCompletionCode => [0:7],
    }
}

impl From<MctpControlMessageHeader> for MctpMessageHeader {
    fn from(header: MctpControlMessageHeader) -> Self {
        let as_u32: u32 = header.try_into().unwrap();
        MctpMessageHeader::try_from(as_u32).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    #[test]
    fn test_mctp_control_message_header_bit_register() {
        assert_eq!(
            MctpControlMessageHeader::try_from(u32::from_be_bytes([
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
            ]))
            .unwrap(),
            MctpControlMessageHeader {
                integrity_check: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            MctpControlMessageHeader::try_from(u32::from_be_bytes([
                0b1000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
            ]))
            .unwrap(),
            MctpControlMessageHeader {
                integrity_check: 1,
                ..Default::default()
            }
        );
    }

    #[rstest]
    #[case(0, 0, 0, 0, MctpCommandCode::SetEndpointId, MctpCompletionCode::Success)]
    #[case(1, 1, 1, 0x1F, MctpCommandCode::GetEndpointId, MctpCompletionCode::Error)]
    #[case(0, 0, 1, 3, MctpCommandCode::QueryHop, MctpCompletionCode::CommandSpecific(0x80))]
    fn serialize_deserialize_roundtrip(
        #[case] integrity_check: u8,
        #[case] request_bit: u8,
        #[case] datagram_bit: u8,
        #[case] instance_id: u8,
        #[case] command_code: MctpCommandCode,
        #[case] completion_code: MctpCompletionCode,
    ) {
        let header = MctpControlMessageHeader {
            integrity_check,
            message_type: MctpMessageType::MctpControl,
            request_bit,
            datagram_bit,
            instance_id,
            command_code,
            completion_code,
        };

        let as_be_bytes = TryInto::<u32>::try_into(header).unwrap().to_be_bytes();
        let parsed = MctpControlMessageHeader::try_from(u32::from_be_bytes(as_be_bytes)).unwrap();
        assert_eq!(parsed, header);
    }

    fn test_into_mctp_message_header() {
        let header = MctpControlMessageHeader {
            integrity_check: 0,
            message_type: MctpMessageType::MctpControl,
            ..Default::default()
        };
        let message_header: MctpMessageHeader = header.into();
        assert_eq!(
            message_header,
            MctpMessageHeader {
                integrity_check: 0,
                message_type: MctpMessageType::MctpControl,
                ..Default::default()
            }
        );
    }
}
