//! This crate provides types for representing the RSDP (the Root System Descriptor Table; the first ACPI table)
//! and methods for searching for it on BIOS systems. Importantly, this crate (unlike `acpi`, which re-exports the
//! contents of this crate) does not need `alloc`, and so can be used in environments that can't allocate. This is
//! specifically meant to be used from bootloaders for finding the RSDP, so it can be passed to the payload. If you
//! don't have this requirement, and want to do more than just find the RSDP, you can use `acpi` instead of this
//! crate.
//!
//! To use this crate, you will need to provide an implementation of `AcpiHandler`. This is the same handler type
//! used in the `acpi` crate.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod handler;

use core::{mem, ops::Range, slice, str};
use handler::{AcpiHandler, PhysicalMapping};
use log::warn;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsdpError {
    NoValidRsdp,
    IncorrectSignature,
    InvalidOemId,
    InvalidChecksum,
}

/// The size in bytes of the ACPI 1.0 RSDP.
const RSDP_V1_LENGTH: usize = 20;
/// The total size in bytes of the RSDP fields introduced in ACPI 2.0.
const RSDP_V2_EXT_LENGTH: usize = mem::size_of::<Rsdp>() - RSDP_V1_LENGTH;
/// The size in bytes covered by the ACPI 2.0+ extended checksum (mirrors Linux ACPI_RSDP_XCHECKSUM_LENGTH).
const RSDP_XCHECKSUM_LENGTH: usize = 36;
/// The first structure found in ACPI. It just tells us where the RSDT is.
///
/// On BIOS systems, it is either found in the first 1KB of the Extended Bios Data Area, or between
/// 0x000E0000 and 0x000FFFFF. The signature is always on a 16 byte boundary. On (U)EFI, it may not
/// be located in these locations, and so an address should be found in the EFI configuration table
/// instead.
///
/// The recommended way of locating the RSDP is to let the bootloader do it - Multiboot2 can pass a
/// tag with the physical address of it. If this is not possible, a manual scan can be done.
///
/// If `revision >= 2`, the RSDP contains the extended fields introduced in ACPI 2.0. Revisions below 2 are
/// handled as legacy RSDPs, matching Linux ACPICA, so these fields are not valid and should not be accessed.
/// For ACPI Version 2.0+, `xsdt_address` should be used when it is non-zero (truncated to `u32` on x86);
/// otherwise, `rsdt_address` should be used.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,

    /*
     * These fields are only valid for ACPI Version 2.0 and greater
     */
    length: u32,
    xsdt_address: u64,
    ext_checksum: u8,
    reserved: [u8; 3],
}

impl Rsdp {
    /// This searches for a RSDP on BIOS systems.
    ///
    /// ### Safety
    /// This function probes memory in three locations:
    ///    - It reads a word from `40:0e` to locate the EBDA.
    ///    - The first 1KiB of the EBDA (Extended BIOS Data Area).
    ///    - The BIOS memory area at `0xe0000..=0xfffff`.
    ///
    /// This should be fine on all BIOS systems. However, UEFI platforms are free to put the RSDP wherever they
    /// please, so this won't always find the RSDP. Further, prodding these memory locations may have unintended
    /// side-effects. On UEFI systems, the RSDP should be found in the Configuration Table, using two GUIDs:
    ///     - ACPI v1.0 structures use `eb9d2d30-2d88-11d3-9a16-0090273fc14d`.
    ///     - ACPI v2.0 or later structures use `8868e871-e4f1-11d3-bc22-0080c73c8881`.
    /// You should search the entire table for the v2.0 GUID before searching for the v1.0 one.
    pub unsafe fn search_for_on_bios<H>(handler: H) -> Result<PhysicalMapping<H, Rsdp>, RsdpError>
    where
        H: AcpiHandler,
    {
        let rsdp_address = find_search_areas(handler.clone()).iter().find_map(|area| {
            // Map the search area for the RSDP followed by `RSDP_V2_EXT_LENGTH` bytes so an ACPI 1.0 RSDP at the
            // end of the area can be read as an `Rsdp` (which always has the size of an ACPI 2.0 RSDP)
            let mapping = unsafe {
                handler.map_physical_region::<u8>(area.start, area.end - area.start + RSDP_V2_EXT_LENGTH)
            };

            let extended_area_bytes =
                unsafe { slice::from_raw_parts(mapping.virtual_start().as_ptr(), mapping.region_length()) };

            // Search `Rsdp`-sized windows at 16-byte boundaries relative to the base of the area (which is also
            // aligned to 16 bytes due to the implementation of `find_search_areas`)
            extended_area_bytes.windows(mem::size_of::<Rsdp>()).step_by(16).find_map(|maybe_rsdp_bytes_slice| {
                let maybe_rsdp_virt_ptr = maybe_rsdp_bytes_slice.as_ptr().cast::<Rsdp>();
                let maybe_rsdp_phys_start = maybe_rsdp_virt_ptr as usize
                    - mapping.virtual_start().as_ptr() as usize
                    + mapping.physical_start();
                // SAFETY: `maybe_rsdp_virt_ptr` points to an aligned, readable `Rsdp`-sized value, and the `Rsdp`
                // struct's fields are always initialized.
                let maybe_rsdp = unsafe { &*maybe_rsdp_virt_ptr };

                match maybe_rsdp.validate() {
                    Ok(()) => Some(maybe_rsdp_phys_start),
                    Err(RsdpError::IncorrectSignature) => None,
                    Err(e) => {
                        warn!("Invalid RSDP found at {:#x}: {:?}", maybe_rsdp_phys_start, e);

                        None
                    }
                }
            })
        });

        match rsdp_address {
            Some(address) => {
                let rsdp_mapping = unsafe { handler.map_physical_region::<Rsdp>(address, mem::size_of::<Rsdp>()) };
                Ok(rsdp_mapping)
            }
            None => Err(RsdpError::NoValidRsdp),
        }
    }

    /// Checks that:
    ///     1) The signature is correct
    ///     2) The checksum is correct
    ///     3) For Version 2.0+, that the extension checksum is correct
    pub fn validate(&self) -> Result<(), RsdpError> {
        // Check the signature
        if self.signature != RSDP_SIGNATURE {
            return Err(RsdpError::IncorrectSignature);
        }

        // Check the OEM id is valid UTF8 (allows use of unwrap)
        if str::from_utf8(&self.oem_id).is_err() {
            return Err(RsdpError::InvalidOemId);
        }

        // Always check the standard checksum over the first 20 bytes (ACPI 1.0 RSDP).
        let standard_bytes = unsafe { slice::from_raw_parts(self as *const Rsdp as *const u8, RSDP_V1_LENGTH) };
        let standard_sum = standard_bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
        if standard_sum != 0 {
            return Err(RsdpError::InvalidChecksum);
        }

        // For ACPI 2.0+ (revision >= 2), also check the extended checksum over 36 bytes.
        if self.revision >= 2 {
            let extended_bytes =
                unsafe { slice::from_raw_parts(self as *const Rsdp as *const u8, RSDP_XCHECKSUM_LENGTH) };
            let extended_sum = extended_bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
            if extended_sum != 0 {
                return Err(RsdpError::InvalidChecksum);
            }
        }

        Ok(())
    }

    pub fn signature(&self) -> [u8; 8] {
        self.signature
    }

    pub fn checksum(&self) -> u8 {
        self.checksum
    }

    pub fn oem_id(&self) -> &str {
        str::from_utf8(&self.oem_id).unwrap()
    }

    pub fn revision(&self) -> u8 {
        self.revision
    }

    pub fn rsdt_address(&self) -> u32 {
        self.rsdt_address
    }

    pub fn length(&self) -> u32 {
        assert!(self.revision >= 2, "Tried to read extended RSDP field with ACPI Version < 2.0");
        self.length
    }

    pub fn xsdt_address(&self) -> u64 {
        assert!(self.revision >= 2, "Tried to read extended RSDP field with ACPI Version < 2.0");
        self.xsdt_address
    }

    pub fn ext_checksum(&self) -> u8 {
        assert!(self.revision >= 2, "Tried to read extended RSDP field with ACPI Version < 2.0");
        self.ext_checksum
    }
}

/// Find the areas we should search for the RSDP in.
pub fn find_search_areas<H>(handler: H) -> [Range<usize>; 2]
where
    H: AcpiHandler,
{
    /*
     * Read the base address of the EBDA from its location in the BDA (BIOS Data Area). Not all BIOSs fill this out
     * unfortunately, so we might not get a sensible result. We shift it left 4, as it's a segment address.
     */
    let ebda_start_mapping =
        unsafe { handler.map_physical_region::<u16>(EBDA_START_SEGMENT_PTR, mem::size_of::<u16>()) };
    let ebda_start = (*ebda_start_mapping as usize) << 4;

    [
        /*
         * The main BIOS area below 1MiB. In practice, from my [Restioson's] testing, the RSDP is more often here
         * than the EBDA. We also don't want to search the entire possibele EBDA range, if we've failed to find it
         * from the BDA.
         */
        RSDP_BIOS_AREA_START..(RSDP_BIOS_AREA_END + 1),
        // Check if base segment ptr is in valid range for EBDA base
        if (EBDA_EARLIEST_START..EBDA_END).contains(&ebda_start) {
            // First KiB of EBDA
            ebda_start..ebda_start + 1024
        } else {
            // We don't know where the EBDA starts, so just search the largest possible EBDA
            EBDA_EARLIEST_START..(EBDA_END + 1)
        },
    ]
}

/// This (usually!) contains the base address of the EBDA (Extended Bios Data Area), shifted right by 4
const EBDA_START_SEGMENT_PTR: usize = 0x40e;
/// The earliest (lowest) memory address an EBDA (Extended Bios Data Area) can start
const EBDA_EARLIEST_START: usize = 0x80000;
/// The end of the EBDA (Extended Bios Data Area)
const EBDA_END: usize = 0x9ffff;
/// The start of the main BIOS area below 1mb in which to search for the RSDP (Root System Description Pointer)
const RSDP_BIOS_AREA_START: usize = 0xe0000;
/// The end of the main BIOS area below 1mb in which to search for the RSDP (Root System Description Pointer)
const RSDP_BIOS_AREA_END: usize = 0xfffff;
/// The RSDP (Root System Description Pointer)'s signature, "RSD PTR " (note trailing space)
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;
    use std::{boxed::Box, vec::Vec};

    /// Build a 36-byte RSDP with both checksums valid.
    fn make_rsdp(revision: u8, rsdt_addr: u32, xsdt_addr: u64, length: u32) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[0..8].copy_from_slice(b"RSD PTR ");
        b[9..15].copy_from_slice(b"TEST01");
        b[15] = revision;
        b[16..20].copy_from_slice(&rsdt_addr.to_le_bytes());
        b[20..24].copy_from_slice(&length.to_le_bytes());
        b[24..32].copy_from_slice(&xsdt_addr.to_le_bytes());
        // Standard 20-byte checksum
        b[8] = 0;
        let s = b[..RSDP_V1_LENGTH].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(s);
        // Extended 36-byte checksum
        b[32] = 0;
        let s = b[..RSDP_XCHECKSUM_LENGTH].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        b[32] = 0u8.wrapping_sub(s);
        b
    }

    unsafe fn as_rsdp(bytes: &[u8; 36]) -> &Rsdp {
        unsafe { &*(bytes.as_ptr() as *const Rsdp) }
    }

    // --- Test 1: compensated checksum rejected ---
    // An ACPI 2.0+ RSDP with a bad 20-byte standard checksum that happens to
    // sum to zero over the full 36 bytes must still be rejected.

    #[test]
    fn compensated_checksum_rejected() {
        let mut bytes = make_rsdp(2, 0x1000, 0xDEAD_BEEF, 36);
        // Corrupt a byte inside the first 20 (not the checksum byte at offset 8)
        bytes[10] ^= 1;
        // Now the 20-byte sum is non-zero, but the 36-byte sum is also non-zero
        // (we broke the 20-byte region which is a subset of the 36-byte region).
        // Fix up the extended checksum so the 36-byte sum becomes 0 again,
        // but leave the 20-byte sum broken.
        bytes[32] = 0;
        let ext_sum = bytes[..RSDP_XCHECKSUM_LENGTH].iter().fold(0u8, |s, &x| s.wrapping_add(x));
        bytes[32] = 0u8.wrapping_sub(ext_sum);

        let rsdp = unsafe { as_rsdp(&bytes) };
        // The dual-stage check must reject this: standard checksum fails first.
        assert_eq!(rsdp.validate(), Err(RsdpError::InvalidChecksum));
    }

    // --- Test 2: revision 1 behavior ---

    #[test]
    fn rev1_ignores_extended_checksum() {
        let mut bytes = make_rsdp(1, 0x1000, 0, 0);
        // Corrupt a byte in the extension area (bytes 20-35) — this is
        // undefined for revision 1 and must not affect validation.
        bytes[33] ^= 1;
        let rsdp = unsafe { as_rsdp(&bytes) };
        assert_eq!(rsdp.validate(), Ok(()));
    }

    #[test]
    fn rev1_bad_standard_checksum_rejected() {
        let mut bytes = make_rsdp(1, 0x1000, 0, 0);
        // Corrupt a byte in the first 20
        bytes[10] ^= 1;
        let rsdp = unsafe { as_rsdp(&bytes) };
        assert_eq!(rsdp.validate(), Err(RsdpError::InvalidChecksum));
    }

    #[test]
    #[should_panic(expected = "Tried to read extended RSDP field with ACPI Version < 2.0")]
    fn rev1_length_panics() {
        let bytes = make_rsdp(1, 0x1000, 0, 0);
        let rsdp = unsafe { as_rsdp(&bytes) };
        let _ = rsdp.length();
    }

    #[test]
    #[should_panic(expected = "Tried to read extended RSDP field with ACPI Version < 2.0")]
    fn rev1_xsdt_address_panics() {
        let bytes = make_rsdp(1, 0x1000, 0, 0);
        let rsdp = unsafe { as_rsdp(&bytes) };
        let _ = rsdp.xsdt_address();
    }

    // --- Mock handler for BIOS search tests ---

    /// A handler that treats physical addresses as offsets into a static buffer.
    #[derive(Clone)]
    struct TestHandler {
        mem: &'static [u8],
    }

    impl AcpiHandler for TestHandler {
        unsafe fn map_physical_region<T>(&self, physical_address: usize, size: usize) -> PhysicalMapping<Self, T> {
            assert!(physical_address + size <= self.mem.len());
            let ptr = unsafe { self.mem.as_ptr().add(physical_address) } as *const T;
            unsafe {
                PhysicalMapping::new(
                    physical_address,
                    NonNull::new(ptr as *mut T).unwrap(),
                    size,
                    size,
                    self.clone(),
                )
            }
        }

        fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {}
    }

    // --- Test 4: last aligned RSDP in BIOS search area ---

    #[test]
    fn last_aligned_rsdp_in_bios_area() {
        // The BIOS search area is 0xE0000..0x100000. The scan maps
        // area.start..area.end+RSDP_V2_EXT_LENGTH, so we need a buffer
        // covering [0, 0x100010).
        let area_start = RSDP_BIOS_AREA_START;
        let area_end = RSDP_BIOS_AREA_END + 1;
        let buf_len = area_end + RSDP_V2_EXT_LENGTH; // 0x100010

        let mut buf: Vec<u8> = std::vec![0; buf_len];

        // Place a valid RSDP at the last 16-byte-aligned position.
        // The extended scan window (step_by(16)) visits offsets
        // area_start + N*16 within the search area as long as
        // N*16 <= area_end - area_start + RSDP_V2_EXT_LENGTH - size_of::<Rsdp>().
        let window_end = area_end - area_start + RSDP_V2_EXT_LENGTH - mem::size_of::<Rsdp>();
        let last_offset = window_end - (window_end % 16);
        let rsdp_phys = area_start + last_offset;

        let rsdp_bytes = make_rsdp(0, 0x1000, 0, 0); // ACPI 1.0 RSDP
        buf[rsdp_phys..rsdp_phys + 36].copy_from_slice(&rsdp_bytes);

        let buf: &'static mut [u8] = Box::leak(buf.into_boxed_slice());
        let handler = TestHandler { mem: buf };

        let result = unsafe { Rsdp::search_for_on_bios(handler) };
        assert!(result.is_ok(), "Should find RSDP at last aligned position");
        assert_eq!(result.unwrap().physical_start(), rsdp_phys);
    }

    #[test]
    fn last_aligned_rsdp_in_ebda_area() {
        // Place a valid EBDA segment pointer at 0x40e so find_search_areas
        // uses the specific EBDA range. We point it to 0x90000 (first KiB).
        let ebda_seg: u16 = (0x90000 >> 4) as u16;
        let ebda_start = (ebda_seg as usize) << 4; // 0x90000

        // The buffer must cover the BIOS search area (searched first) through
        // the EBDA area. Use the BIOS area end as a lower bound.
        let buf_len =
            usize::max(RSDP_BIOS_AREA_END + 1 + RSDP_V2_EXT_LENGTH, ebda_start + 1024 + RSDP_V2_EXT_LENGTH);

        let mut buf: Vec<u8> = std::vec![0; buf_len];
        buf[EBDA_START_SEGMENT_PTR..EBDA_START_SEGMENT_PTR + 2].copy_from_slice(&ebda_seg.to_le_bytes());

        // Place RSDP at the last 16-byte-aligned position in the EBDA KiB
        let window_end = 1024 + RSDP_V2_EXT_LENGTH - mem::size_of::<Rsdp>();
        let last_offset = window_end - (window_end % 16);
        let rsdp_phys = ebda_start + last_offset;
        let rsdp_bytes = make_rsdp(0, 0x1000, 0, 0);
        buf[rsdp_phys..rsdp_phys + 36].copy_from_slice(&rsdp_bytes);

        let buf: &'static mut [u8] = Box::leak(buf.into_boxed_slice());
        let handler = TestHandler { mem: buf };

        let result = unsafe { Rsdp::search_for_on_bios(handler) };
        assert!(result.is_ok(), "Should find RSDP at last aligned position in EBDA");
        assert_eq!(result.unwrap().physical_start(), rsdp_phys);
    }
}
