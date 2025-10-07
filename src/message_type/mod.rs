mod mctp_control;
#[cfg(feature = "odp")]
pub mod odp;
mod vendor_defined_pci;

use crate::{MctpMedium, error::MctpPacketResult};
pub use mctp_control::*;
#[cfg(feature = "odp")]
pub use odp::*;
pub use vendor_defined_pci::*;

pub trait MctpMessageHeaderTrait: Sized {
    fn serialize<M: MctpMedium>(self, buffer: &mut [u8]) -> MctpPacketResult<usize, M>;

    fn deserialize<M: MctpMedium>(buffer: &[u8]) -> MctpPacketResult<(Self, &[u8]), M>;
}

pub trait MctpMessageTrait<'buf>: Sized {
    const MESSAGE_TYPE: u8;
    type Header: MctpMessageHeaderTrait;

    fn serialize<M: MctpMedium>(self, buffer: &mut [u8]) -> MctpPacketResult<usize, M>;

    fn deserialize<M: MctpMedium>(
        header: &Self::Header,
        buffer: &'buf [u8],
    ) -> MctpPacketResult<Self, M>;
}
