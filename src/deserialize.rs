use crate::{
    MctpMessageBuffer, MctpPacketError,
    buffer_encoding::{BufferEncoding, DecodeError},
    error::MctpPacketResult,
    mctp_transport_header::MctpTransportHeader,
    medium::MctpMedium,
};

pub(crate) fn parse_transport_header<M: MctpMedium>(
    packet: &[u8],
) -> MctpPacketResult<(MctpTransportHeader, &[u8]), M> {
    // Walk 4 decoded bytes through the medium's BufferEncoding. We do NOT
    // pre-check `packet.len() < 4` because for stuffing encodings that's
    // misleading: wire length is not decoded length. PrematureEnd from
    // read_byte is the canonical "ran out of bytes while decoding the header"
    // signal — it correctly handles BOTH the Passthrough case (wire < 4) AND
    // the stuffing case (wire >= 4 but yields < 4 decoded bytes).
    let mut header_bytes = [0u8; 4];
    let mut wire_cursor = 0;
    for slot in header_bytes.iter_mut() {
        let (byte, n) = <M::Encoding as BufferEncoding>::read_byte(&packet[wire_cursor..])
            .map_err(|e| match e {
                DecodeError::PrematureEnd => MctpPacketError::HeaderParseError(
                    "Packet is too small, cannot parse transport header",
                ),
                DecodeError::InvalidEscape => MctpPacketError::HeaderParseError(
                    "Invalid encoding escape sequence in transport header",
                ),
            })?;
        *slot = byte;
        wire_cursor += n;
    }
    let transport_header_value = u32::from_be_bytes(header_bytes);
    let transport_header = MctpTransportHeader::try_from(transport_header_value)
        .map_err(|_| MctpPacketError::HeaderParseError("Invalid transport header"))?;
    Ok((transport_header, &packet[wire_cursor..]))
}

pub(crate) fn parse_message_body<M: MctpMedium>(
    packet: &[u8],
) -> MctpPacketResult<(MctpMessageBuffer<'_>, Option<u8>), M> {
    // first four bytes are the message header, parse with MctpMessageHeader
    // to figure out the type, then based on that, parse the type specific header
    if packet.is_empty() {
        return Err(MctpPacketError::HeaderParseError(
            "packet too small to extract message type from header",
        ));
    }

    let integrity_check = packet[0] & 0b1000_0000;
    let message_type = packet[0] & 0b0111_1111;
    let packet = &packet[1..];

    // TODO - compute message integrity check if header.integrity_check is set
    Ok((
        MctpMessageBuffer {
            integrity_check,
            message_type,
            rest: packet,
        },
        None,
    ))
}
