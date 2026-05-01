use crate::{
    MctpPacketError,
    buffer_encoding::{EncodeError, EncodingEncoder},
    error::MctpPacketResult,
    mctp_packet_context::MctpReplyContext,
    mctp_transport_header::MctpTransportHeader,
    medium::MctpMedium,
};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SerializePacketState<'buf, M: MctpMedium> {
    pub(crate) medium: &'buf M,
    pub(crate) reply_context: MctpReplyContext<M>,
    pub(crate) current_packet_num: u8,
    pub(crate) serialized_message_header: bool,
    pub(crate) message_buffer: &'buf [u8],
    pub(crate) assembly_buffer: &'buf mut [u8],
}

pub const TRANSPORT_HEADER_SIZE: usize = 4;

impl<'buf, M: MctpMedium> SerializePacketState<'buf, M> {
    pub fn next(&mut self) -> Option<MctpPacketResult<&[u8], M>> {
        if self.message_buffer.is_empty() {
            return None;
        }

        let packet = self.medium.serialize(
            self.reply_context.medium_context,
            self.assembly_buffer,
            |encoder: &mut EncodingEncoder<'_, M::Encoding>| {
                let max_packet_size = self
                    .medium
                    .max_message_body_size()
                    .min(encoder.remaining_wire());
                if max_packet_size < TRANSPORT_HEADER_SIZE {
                    return Err(MctpPacketError::SerializeError(
                        "assembly buffer too small for mctp transport header",
                    ));
                }

                let message_size =
                    (max_packet_size - TRANSPORT_HEADER_SIZE).min(self.message_buffer.len());

                // if there is no room for any of the body, and the body is not empty,
                // then return an error, otherwise we infinate loop sending packets with headers and
                // no body, making it impossible to ever assemble a message
                if message_size == 0 && !self.message_buffer.is_empty() {
                    return Err(MctpPacketError::SerializeError(
                        "assembly buffer too small for non-empty message body",
                    ));
                }

                let body = &self.message_buffer[..message_size];
                self.message_buffer = &self.message_buffer[message_size..];

                let start_of_message = if self.current_packet_num == 0 { 1 } else { 0 };
                let end_of_message = if self.message_buffer.is_empty() { 1 } else { 0 };
                let packet_sequence_number = self.reply_context.packet_sequence_number.inc();
                let transport_header: u32 = MctpTransportHeader {
                    reserved: 0,
                    header_version: 1,
                    start_of_message,
                    end_of_message,
                    packet_sequence_number,
                    tag_owner: 0,
                    message_tag: self.reply_context.message_tag,
                    source_endpoint_id: self.reply_context.destination_endpoint_id,
                    destination_endpoint_id: self.reply_context.source_endpoint_id,
                }
                .try_into()
                .map_err(MctpPacketError::SerializeError)?;

                // write the transport header and message body via the
                // medium-supplied encoder.
                let map_encode_err = |e: EncodeError| match e {
                    EncodeError::BufferFull => {
                        MctpPacketError::SerializeError("encoding: buffer full")
                    }
                };
                encoder
                    .write_all(&transport_header.to_be_bytes())
                    .map_err(map_encode_err)?;
                encoder.write_all(body).map_err(map_encode_err)?;
                Ok(())
            },
        );

        // Increment packet number for next call
        if packet.is_ok() {
            self.current_packet_num += 1;
        }

        Some(packet)
    }
}
