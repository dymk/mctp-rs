//! DSP0253 byte-stuffed serial medium for MCTP.
//!
//! Two-layer split:
//!   - [`SerialEncoding`]: stateless byte-stuffing (0x7E, 0x7D escape pair).
//!   - [`MctpSerialMedium`]: framing (revision byte, byte_count, body, FCS-16, end-flag).
//!
//! Both layers are gated behind the `serial` cargo feature.

use crate::{
    MctpPacketError,
    buffer_encoding::{BufferEncoding, DecodeError, EncodeError, EncodingDecoder, EncodingEncoder},
    error::MctpPacketResult,
    medium::{MctpMedium, MctpMediumFrame},
};

/// DSP0253 byte-stuffing transform. Stateless ZST.
///
/// Encode: `0x7E -> [0x7D, 0x5E]`, `0x7D -> [0x7D, 0x5D]`, any other
/// byte -> `[b]`.
/// Decode: `0x7D 0x5E -> 0x7E`, `0x7D 0x5D -> 0x7D`, `0x7D <other>` ->
/// `InvalidEscape`.
///
/// Raw `0x7E` in the wire stream is NOT rejected here — that's a
/// framing concern owned by `MctpSerialMedium::deserialize`, which
/// checks the body region for stray flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SerialEncoding;

impl BufferEncoding for SerialEncoding {
    fn write_byte(wire_buf: &mut [u8], byte: u8) -> Result<usize, EncodeError> {
        match byte {
            0x7E => {
                if wire_buf.len() < 2 {
                    return Err(EncodeError::BufferFull);
                }
                wire_buf[0] = 0x7D;
                wire_buf[1] = 0x5E;
                Ok(2)
            }
            0x7D => {
                if wire_buf.len() < 2 {
                    return Err(EncodeError::BufferFull);
                }
                wire_buf[0] = 0x7D;
                wire_buf[1] = 0x5D;
                Ok(2)
            }
            b => match wire_buf.first_mut() {
                Some(slot) => {
                    *slot = b;
                    Ok(1)
                }
                None => Err(EncodeError::BufferFull),
            },
        }
    }

    fn read_byte(wire_buf: &[u8]) -> Result<(u8, usize), DecodeError> {
        match wire_buf.first().copied() {
            None => Err(DecodeError::PrematureEnd),
            Some(0x7D) => match wire_buf.get(1).copied() {
                None => Err(DecodeError::PrematureEnd),
                Some(0x5E) => Ok((0x7E, 2)),
                Some(0x5D) => Ok((0x7D, 2)),
                Some(_) => Err(DecodeError::InvalidEscape),
            },
            // Raw 0x7E falls through here as a 1-byte read; the framing
            // layer (`MctpSerialMedium::deserialize`) rejects bare
            // 0x7E inside the body region.
            Some(b) => Ok((b, 1)),
        }
    }

    fn wire_size_of(decoded: &[u8]) -> usize {
        decoded
            .iter()
            .map(|&b| if b == 0x7E || b == 0x7D { 2 } else { 1 })
            .sum()
    }
}

/// SP MCTP endpoint id per CONTEXT D-D-06.
pub const SP_EID: crate::endpoint_id::EndpointId = crate::endpoint_id::EndpointId::Id(0x08);
/// EC MCTP endpoint id per CONTEXT D-D-06.
pub const EC_EID: crate::endpoint_id::EndpointId = crate::endpoint_id::EndpointId::Id(0x0A);
/// Maximum DSP0253 packet body size (DECODED bytes, before stuffing).
pub const CONST_MTU: usize = 251;

const SERIAL_REVISION: u8 = 0x01;
const END_FLAG: u8 = 0x7E;
/// Header bytes: revision + byte_count (decoded body byte count).
const HEADER_LEN: usize = 2;
/// Worst-case trailer wire bytes: 2 stuffed FCS bytes (each may
/// expand 1 -> 2) + 1 end-flag.
const MAX_TRAILER_WIRE: usize = 5;

// CRC-16/X-25 per DSP0253 §8 (poly 0x1021, init 0xFFFF, refin/refout,
// xorout 0xFFFF). Algorithm catalog entry locked in CONTEXT D-D-02.
// FCS bytes on the wire are MSB-first per DSP0253 §5.2 (overrides
// RFC1662's LSB-first PPP convention).
const FCS_ALGO: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MctpSerialMediumFrame {
    pub revision: u8,
    /// DECODED body byte count per DSP0253 §6.2 (NOT the wire byte
    /// count). Cap = `CONST_MTU` = 251; max u8 = 255, fits comfortably.
    pub byte_count: u8,
    pub fcs: u16,
}

impl MctpMediumFrame<MctpSerialMedium> for MctpSerialMediumFrame {
    fn packet_size(&self) -> usize {
        // packet_size is the DECODED body byte count — the contract
        // used by `MctpPacketContext::deserialize_packet`, which then
        // subtracts 4 for the transport header.
        self.byte_count as usize
    }

    fn reply_context(&self) {}
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MctpSerialMedium;

impl MctpMedium for MctpSerialMedium {
    type Frame = MctpSerialMediumFrame;
    type Error = &'static str;
    type ReplyContext = ();
    type Encoding = SerialEncoding;

    fn max_message_body_size(&self) -> usize {
        CONST_MTU
    }

    fn deserialize<'buf>(
        &self,
        packet: &'buf [u8],
    ) -> MctpPacketResult<(Self::Frame, EncodingDecoder<'buf, Self::Encoding>), Self> {
        // Minimum frame: 2 header + 0 body + 2 FCS (unstuffed) + 1 end-flag = 5 bytes.
        if packet.len() < HEADER_LEN + 3 {
            return Err(MctpPacketError::MediumError(
                "packet too short for serial frame",
            ));
        }
        let revision = packet[0];
        if revision != SERIAL_REVISION {
            return Err(MctpPacketError::MediumError("unsupported serial revision"));
        }
        let byte_count = packet[1];
        if (byte_count as usize) > CONST_MTU {
            return Err(MctpPacketError::MediumError("byte_count exceeds MTU"));
        }

        // Single forward walk: un-stuff body bytes (count must equal
        // `byte_count`), un-stuff 2 FCS bytes, expect end-flag, compare
        // CRC.
        let body_wire_start = HEADER_LEN;
        let mut decoded = [0u8; CONST_MTU];
        let mut decoded_len = 0usize;
        let mut wire_pos = 0usize; // offset from body_wire_start

        while decoded_len < byte_count as usize {
            let (b, n) =
                SerialEncoding::read_byte(&packet[body_wire_start + wire_pos..]).map_err(|e| {
                    match e {
                        DecodeError::PrematureEnd => {
                            MctpPacketError::MediumError("premature end in body")
                        }
                        DecodeError::InvalidEscape => {
                            MctpPacketError::MediumError("invalid escape in body")
                        }
                    }
                })?;
            if b == END_FLAG {
                // Bare 0x7E inside the body region is a protocol error
                // (MEDIUM-05).
                return Err(MctpPacketError::MediumError("unexpected 0x7E in body"));
            }
            decoded[decoded_len] = b;
            decoded_len += 1;
            wire_pos += n;
        }
        let body_wire_end = body_wire_start + wire_pos;

        // Un-stuff 2 FCS bytes (DSP0253 §7.1 stuffing applies to FCS).
        let (fcs_msb, n_msb) = SerialEncoding::read_byte(&packet[body_wire_end..])
            .map_err(|_| MctpPacketError::MediumError("invalid escape in fcs"))?;
        let (fcs_lsb, n_lsb) = SerialEncoding::read_byte(&packet[body_wire_end + n_msb..])
            .map_err(|_| MctpPacketError::MediumError("invalid escape in fcs"))?;
        let trailer_pos = body_wire_end + n_msb + n_lsb;

        if trailer_pos >= packet.len() || packet[trailer_pos] != END_FLAG {
            return Err(MctpPacketError::MediumError("missing end flag"));
        }
        if trailer_pos + 1 != packet.len() {
            return Err(MctpPacketError::MediumError(
                "trailing bytes after end flag",
            ));
        }

        // FCS-16/X-25 over un-stuffed (revision || byte_count || decoded body).
        let mut digest = FCS_ALGO.digest();
        digest.update(&[revision, byte_count]);
        digest.update(&decoded[..decoded_len]);
        let computed_fcs = digest.finalize();
        // DSP0253 §5.2: MSB first on wire.
        let wire_fcs = u16::from_be_bytes([fcs_msb, fcs_lsb]);
        if wire_fcs != computed_fcs {
            return Err(MctpPacketError::MediumError("fcs mismatch"));
        }

        Ok((
            MctpSerialMediumFrame {
                revision,
                byte_count,
                fcs: wire_fcs,
            },
            EncodingDecoder::<Self::Encoding>::new(&packet[body_wire_start..body_wire_end]),
        ))
    }

    fn serialize<'buf, F>(
        &self,
        _reply_context: Self::ReplyContext,
        buffer: &'buf mut [u8],
        message_writer: F,
    ) -> MctpPacketResult<&'buf [u8], Self>
    where
        F: for<'a> FnOnce(&mut EncodingEncoder<'a, Self::Encoding>) -> MctpPacketResult<(), Self>,
    {
        if buffer.len() < HEADER_LEN + MAX_TRAILER_WIRE {
            return Err(MctpPacketError::MediumError(
                "buffer too small for serial frame",
            ));
        }
        let buffer_len = buffer.len();

        // Run closure over body region (reserve worst-case 5-byte
        // trailer). The encoder stuffs body bytes via
        // `SerialEncoding::write_byte` automatically.
        let body_wire_len = {
            let body_buf = &mut buffer[HEADER_LEN..buffer_len - MAX_TRAILER_WIRE];
            let mut encoder = EncodingEncoder::<Self::Encoding>::new(body_buf);
            message_writer(&mut encoder)?;
            encoder.wire_position()
        };

        // Re-decode body to recover DECODED bytes + decoded count for
        // `byte_count` and FCS. CONTEXT D-B-02 acknowledges the
        // double-walk; ~250 bytes max, no_std, cheap.
        let mut decoded = [0u8; CONST_MTU];
        let mut decoded_len = 0usize;
        let mut wire_pos = 0usize;
        while wire_pos < body_wire_len {
            let (b, n) = SerialEncoding::read_byte(
                &buffer[HEADER_LEN + wire_pos..HEADER_LEN + body_wire_len],
            )
            .map_err(|_| MctpPacketError::MediumError("internal: failed to re-decode body"))?;
            if decoded_len >= CONST_MTU {
                return Err(MctpPacketError::MediumError("body exceeds MTU"));
            }
            decoded[decoded_len] = b;
            decoded_len += 1;
            wire_pos += n;
        }
        // Should not fire — `EncodingEncoder::write` returns
        // `BufferFull` long before decoded_len could exceed 251.
        if decoded_len > u8::MAX as usize {
            return Err(MctpPacketError::MediumError(
                "body exceeds byte_count u8 cap",
            ));
        }
        let byte_count = decoded_len as u8;

        // FCS-16/X-25 over un-stuffed (revision || byte_count || decoded body).
        let mut digest = FCS_ALGO.digest();
        digest.update(&[SERIAL_REVISION, byte_count]);
        digest.update(&decoded[..decoded_len]);
        let fcs = digest.finalize();
        // DSP0253 §5.2: MSB first on wire.
        let [fcs_msb, fcs_lsb] = fcs.to_be_bytes();

        // Header: revision + byte_count emitted directly (NOT stuffed),
        // matching `SmbusEspiMedium`'s header pattern. See PLAN
        // <behavior> note for the conformance caveat when byte_count
        // happens to equal 0x7E or 0x7D — round-trips cleanly through
        // this implementation's deserialize.
        buffer[0] = SERIAL_REVISION;
        buffer[1] = byte_count;

        // Stuff and write FCS bytes via SerialEncoding (DSP0253 §7.1 +
        // CONTEXT D-B-02 — deserialize un-stuffs FCS, so serialize
        // must stuff).
        let fcs_start = HEADER_LEN + body_wire_len;
        let n_msb = SerialEncoding::write_byte(&mut buffer[fcs_start..], fcs_msb)
            .map_err(|_| MctpPacketError::MediumError("internal: failed to encode fcs"))?;
        let n_lsb = SerialEncoding::write_byte(&mut buffer[fcs_start + n_msb..], fcs_lsb)
            .map_err(|_| MctpPacketError::MediumError("internal: failed to encode fcs"))?;
        let end_pos = fcs_start + n_msb + n_lsb;

        // End-flag is written directly (flags are NOT stuffed by
        // definition).
        buffer[end_pos] = END_FLAG;

        Ok(&buffer[..end_pos + 1])
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use crate::buffer_encoding::EncodingDecoder;

    #[test]
    fn write_byte_stuffs_7e() {
        let mut buf = [0u8; 4];
        let n = SerialEncoding::write_byte(&mut buf, 0x7E).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x7D, 0x5E]);
    }

    #[test]
    fn write_byte_stuffs_7d() {
        let mut buf = [0u8; 4];
        let n = SerialEncoding::write_byte(&mut buf, 0x7D).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x7D, 0x5D]);
    }

    #[test]
    fn write_byte_passthrough_plain() {
        let mut buf = [0u8; 1];
        let n = SerialEncoding::write_byte(&mut buf, 0x41).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0x41]);
    }

    #[test]
    fn write_byte_full_buffer_plain() {
        let mut buf = [];
        assert_eq!(
            SerialEncoding::write_byte(&mut buf, 0x41).unwrap_err(),
            EncodeError::BufferFull
        );
    }

    #[test]
    fn write_byte_full_buffer_escape() {
        let mut buf = [0u8; 1];
        assert_eq!(
            SerialEncoding::write_byte(&mut buf, 0x7E).unwrap_err(),
            EncodeError::BufferFull
        );
    }

    #[test]
    fn read_byte_unstuffs_7e() {
        assert_eq!(SerialEncoding::read_byte(&[0x7D, 0x5E]).unwrap(), (0x7E, 2));
    }

    #[test]
    fn read_byte_unstuffs_7d() {
        assert_eq!(SerialEncoding::read_byte(&[0x7D, 0x5D]).unwrap(), (0x7D, 2));
    }

    #[test]
    fn read_byte_passthrough_plain() {
        assert_eq!(SerialEncoding::read_byte(&[0x41]).unwrap(), (0x41, 1));
    }

    #[test]
    fn read_byte_raw_7e_passes_through() {
        // Raw 0x7E is NOT rejected at the encoding layer — framing is
        // the framing layer's concern.
        assert_eq!(SerialEncoding::read_byte(&[0x7E]).unwrap(), (0x7E, 1));
    }

    #[test]
    fn read_byte_premature_end_empty() {
        assert_eq!(
            SerialEncoding::read_byte(&[]).unwrap_err(),
            DecodeError::PrematureEnd
        );
    }

    #[test]
    fn read_byte_premature_end_after_escape() {
        assert_eq!(
            SerialEncoding::read_byte(&[0x7D]).unwrap_err(),
            DecodeError::PrematureEnd
        );
    }

    #[test]
    fn read_byte_invalid_escape() {
        assert_eq!(
            SerialEncoding::read_byte(&[0x7D, 0xAA]).unwrap_err(),
            DecodeError::InvalidEscape
        );
    }

    #[test]
    fn wire_size_of_mixed() {
        assert_eq!(
            SerialEncoding::wire_size_of(&[0x41, 0x7E, 0x42, 0x7D, 0x43]),
            7
        );
    }

    #[test]
    fn wire_size_of_empty() {
        assert_eq!(SerialEncoding::wire_size_of(&[]), 0);
    }

    #[test]
    fn roundtrip_all_byte_values() {
        // 256-byte payload of every byte value, encoded into a 512-byte
        // wire buffer (worst case is 2x expansion if every byte stuffs;
        // actual expansion here is 256 + 2 = 258 wire bytes).
        let mut decoded = [0u8; 256];
        for (i, slot) in decoded.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut wire = [0u8; 512];
        let mut wpos = 0usize;
        for &b in &decoded {
            wpos += SerialEncoding::write_byte(&mut wire[wpos..], b).unwrap();
        }
        assert_eq!(wpos, SerialEncoding::wire_size_of(&decoded));
        let mut dec = EncodingDecoder::<SerialEncoding>::new(&wire[..wpos]);
        for &expected in &decoded {
            assert_eq!(dec.read().unwrap(), expected);
        }
        assert_eq!(dec.read().unwrap_err(), DecodeError::PrematureEnd);
    }
}
