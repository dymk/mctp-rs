//! DSP0253 byte-stuffed serial medium for MCTP.
//!
//! Two-layer split:
//!   - [`SerialEncoding`]: stateless byte-stuffing (0x7E, 0x7D escape pair).
//!   - `MctpSerialMedium` (added in Task 4): framing (revision byte, byte_count, body, FCS-16,
//!     end-flag).
//!
//! Both layers are gated behind the `serial` cargo feature.

use crate::buffer_encoding::{BufferEncoding, DecodeError, EncodeError};

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
