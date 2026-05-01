use crate::{
    MctpMessageBuffer, MctpPacketError,
    buffer_encoding::{BufferEncoding, DecodeError},
    error::MctpPacketResult,
    mctp_transport_header::MctpTransportHeader,
    medium::MctpMedium,
};

fn map_decode_error<M: MctpMedium>(err: DecodeError) -> MctpPacketError<M> {
    match err {
        DecodeError::PrematureEnd => {
            MctpPacketError::HeaderParseError("encoding: premature end of buffer")
        }
        DecodeError::InvalidEscape => {
            MctpPacketError::HeaderParseError("encoding: invalid escape sequence")
        }
    }
}

pub(crate) fn parse_transport_header<M: MctpMedium>(
    packet: &[u8],
) -> MctpPacketResult<(MctpTransportHeader, &[u8]), M> {
    // Necessary lower bound for any BufferEncoding: each decoded byte requires
    // at least one wire byte. Preserves the original pre-encoding error message.
    if packet.len() < 4 {
        return Err(MctpPacketError::HeaderParseError(
            "Packet is too small, cannot parse transport header",
        ));
    }
    let mut header_bytes = [0u8; 4];
    let mut wire_cursor = 0;
    for slot in header_bytes.iter_mut() {
        let (byte, n) = <M::Encoding as BufferEncoding>::read_byte(&packet[wire_cursor..])
            .map_err(map_decode_error::<M>)?;
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
