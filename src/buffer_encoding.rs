//! Stateless byte-level buffer-encoding transform for MCTP media.
//!
//! Most media (SMBus/eSPI) ship MCTP packets verbatim — wire bytes ARE
//! payload bytes. Some media (DSP0253 serial) need byte-stuffing: an
//! escape character expands certain payload bytes into 2-byte sequences
//! on the wire, and decode reverses that transform.
//!
//! [`BufferEncoding`] is the byte-stuffing layer ONLY. It is stateless:
//! [`write_byte`](BufferEncoding::write_byte) and
//! [`read_byte`](BufferEncoding::read_byte) are associated functions with
//! no `self` and no struct state. The caller manages all cursors into the
//! buffer they own.
//!
//! Higher-level framing concerns — start/end delimiters, FCS / CRC
//! computation — are NOT part of this trait. They live on the medium
//! type itself (e.g., `MctpSerialMedium::decode_frame_in_place` in a
//! later phase) which can use `BufferEncoding` for the byte-stuffing
//! step while owning the framing logic separately.
//!
//! Single-buffer in-place transformation is the design intent. For
//! decode, escape sequences shrink (2 wire bytes → 1 payload byte) so a
//! caller can read with one cursor and write back into the same buffer
//! with a lagging write cursor. For encode, escape sequences grow, so
//! the caller either uses a separate output buffer or pre-shifts the
//! payload — that choreography is the caller's job, not this trait's.

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EncodeError {
    /// `wire_buf` did not have room for the encoded bytes (1 for plain,
    /// up to 2 for an escape sequence). The caller should advance no
    /// cursors and treat the encode as failed.
    BufferFull,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DecodeError {
    /// `wire_buf` was empty or ended mid-escape-sequence. Indicates the
    /// caller asked to decode past the end of valid wire data.
    PrematureEnd,
    /// An escape byte was followed by a byte not in the medium's
    /// accept-list (strict-XOR rule per RFC1662 §4.2 / DSP0253 §6.4).
    /// The caller should reject the entire frame.
    InvalidEscape,
}

/// Stateless byte-stuffing transform. Implementors define how a single
/// logical (payload) byte maps to one or more wire bytes (encode) and
/// how a wire-byte prefix maps back to a single payload byte (decode).
///
/// All methods are associated functions — there is no `self` and no
/// struct state. Callers own the buffers and the read/write cursors.
pub trait BufferEncoding {
    /// Encode one logical payload byte into `wire_buf` starting at
    /// index 0. Returns the number of wire bytes written (1 for plain,
    /// 2 for an escape sequence). The caller advances their write
    /// cursor by the returned count.
    fn write_byte(wire_buf: &mut [u8], byte: u8) -> Result<usize, EncodeError>;

    /// Decode the next logical payload byte from `wire_buf` starting at
    /// index 0. Returns `(decoded_byte, wire_bytes_consumed)`. The
    /// caller advances their read cursor by `wire_bytes_consumed`.
    fn read_byte(wire_buf: &[u8]) -> Result<(u8, usize), DecodeError>;
}

/// No-op encoding: wire bytes ARE payload bytes. Used by media that do
/// not byte-stuff (SMBus/eSPI, test fixtures).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PassthroughEncoding;

impl BufferEncoding for PassthroughEncoding {
    fn write_byte(wire_buf: &mut [u8], byte: u8) -> Result<usize, EncodeError> {
        match wire_buf.first_mut() {
            Some(slot) => {
                *slot = byte;
                Ok(1)
            }
            None => Err(EncodeError::BufferFull),
        }
    }

    fn read_byte(wire_buf: &[u8]) -> Result<(u8, usize), DecodeError> {
        match wire_buf.first() {
            Some(&byte) => Ok((byte, 1)),
            None => Err(DecodeError::PrematureEnd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_write_byte_writes_one_byte() {
        let mut buf = [0u8; 4];
        let n = PassthroughEncoding::write_byte(&mut buf, 0xAB).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf, [0xAB, 0, 0, 0]);
    }

    #[test]
    fn passthrough_write_byte_full_buffer() {
        let mut buf = [];
        let err = PassthroughEncoding::write_byte(&mut buf, 0xAB).unwrap_err();
        assert_eq!(err, EncodeError::BufferFull);
    }

    #[test]
    fn passthrough_read_byte_reads_one_byte() {
        let buf = [0xAB, 0xCD];
        let (b, n) = PassthroughEncoding::read_byte(&buf).unwrap();
        assert_eq!(b, 0xAB);
        assert_eq!(n, 1);
    }

    #[test]
    fn passthrough_read_byte_premature_end() {
        let buf = [];
        let err = PassthroughEncoding::read_byte(&buf).unwrap_err();
        assert_eq!(err, DecodeError::PrematureEnd);
    }

    #[test]
    fn passthrough_round_trip() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        let mut wire = [0u8; 4];
        let mut wire_pos = 0;
        for &b in &payload {
            wire_pos += PassthroughEncoding::write_byte(&mut wire[wire_pos..], b).unwrap();
        }
        assert_eq!(wire_pos, 4);
        assert_eq!(wire, payload);

        let mut decoded = [0u8; 4];
        let mut read_pos = 0;
        let mut write_pos = 0;
        while read_pos < wire_pos {
            let (b, n) = PassthroughEncoding::read_byte(&wire[read_pos..wire_pos]).unwrap();
            decoded[write_pos] = b;
            read_pos += n;
            write_pos += 1;
        }
        assert_eq!(write_pos, 4);
        assert_eq!(decoded, payload);
    }
}
