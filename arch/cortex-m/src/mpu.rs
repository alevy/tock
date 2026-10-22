// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Cortex-M Memory Protection Unit (MPU)
//!
//! Implementation of the memory protection unit for the Cortex-M0+, Cortex-M3,
//! Cortex-M4, and Cortex-M7.

use core::cell::Cell;
use core::cmp;
use core::fmt;
use core::num::NonZeroUsize;

use kernel::platform::mpu;
use kernel::utilities::StaticRef;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::math;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{FieldValue, ReadOnly, ReadWrite, register_bitfields};

/// Smallest allowable MPU region across all CortexM cores
/// Individual cores may have bigger min sizes, but never lower than 32
const CORTEXM_MIN_REGION_SIZE: usize = 32;

/// MPU Registers for the Cortex-M3, Cortex-M4 and Cortex-M7 families
/// Described in section 4.5 of
/// <http://infocenter.arm.com/help/topic/com.arm.doc.dui0553a/DUI0553A_cortex_m4_dgug.pdf>
#[repr(C)]
pub struct MpuRegisters {
    /// Indicates whether the MPU is present and, if so, how many regions it
    /// supports.
    pub mpu_type: ReadOnly<u32, Type::Register>,

    /// The control register:
    ///   * Enables the MPU (bit 0).
    ///   * Enables MPU in hard-fault, non-maskable interrupt (NMI).
    ///   * Enables the default memory map background region in privileged mode.
    pub ctrl: ReadWrite<u32, Control::Register>,

    /// Selects the region number (zero-indexed) referenced by the region base
    /// address and region attribute and size registers.
    pub rnr: ReadWrite<u32, RegionNumber::Register>,

    /// Defines the base address of the currently selected MPU region.
    pub rbar: ReadWrite<u32, RegionBaseAddress::Register>,

    /// Defines the region size and memory attributes of the selected MPU
    /// region. The bits are defined as in 4.5.5 of the Cortex-M4 user guide.
    pub rasr: ReadWrite<u32, RegionAttributes::Register>,
}

register_bitfields![u32,
    Type [
        /// The number of MPU instructions regions supported. Always reads 0.
        IREGION OFFSET(16) NUMBITS(8) [],
        /// The number of data regions supported. If this field reads-as-zero the
        /// processor does not implement an MPU
        DREGION OFFSET(8) NUMBITS(8) [],
        /// Indicates whether the processor support unified (0) or separate
        /// (1) instruction and data regions. Always reads 0 on the
        /// Cortex-M4.
        SEPARATE OFFSET(0) NUMBITS(1) []
    ],

    Control [
        /// Enables privileged software access to the default
        /// memory map
        PRIVDEFENA OFFSET(2) NUMBITS(1) [
            Enable = 0,
            Disable = 1
        ],
        /// Enables the operation of MPU during hard fault, NMI,
        /// and FAULTMASK handlers
        HFNMIENA OFFSET(1) NUMBITS(1) [
            Enable = 0,
            Disable = 1
        ],
        /// Enables the MPU
        ENABLE OFFSET(0) NUMBITS(1) [
            Disable = 0,
            Enable = 1
        ]
    ],

    RegionNumber [
        /// Region indicating the MPU region referenced by the MPU_RBAR and
        /// MPU_RASR registers. Range 0-7 corresponding to the MPU regions.
        REGION OFFSET(0) NUMBITS(8) []
    ],

    RegionBaseAddress [
        /// Base address of the currently selected MPU region.
        ADDR OFFSET(5) NUMBITS(27) [],
        /// MPU Region Number valid bit.
        VALID OFFSET(4) NUMBITS(1) [
            /// Use the base address specified in Region Number Register (RNR)
            UseRNR = 0,
            /// Use the value of the REGION field in this register (RBAR)
            UseRBAR = 1
        ],
        /// Specifies which MPU region to set if VALID is set to 1.
        REGION OFFSET(0) NUMBITS(4) []
    ],

    RegionAttributes [
        /// Enables instruction fetches/execute permission
        XN OFFSET(28) NUMBITS(1) [
            Enable = 0,
            Disable = 1
        ],
        /// Defines access permissions
        AP OFFSET(24) NUMBITS(3) [
            //                                 Privileged  Unprivileged
            //                                 Access      Access
            NoAccess = 0b000,               // --          --
            PrivilegedOnly = 0b001,         // RW          --
            UnprivilegedReadOnly = 0b010,   // RW          R-
            ReadWrite = 0b011,              // RW          RW
            Reserved = 0b100,               // undef       undef
            PrivilegedOnlyReadOnly = 0b101, // R-          --
            ReadOnly = 0b110,               // R-          R-
            ReadOnlyAlias = 0b111           // R-          R-
        ],
        /// Subregion disable bits
        SRD OFFSET(8) NUMBITS(8) [],
        /// Specifies the region size, being 2^(SIZE+1) (minimum 3)
        SIZE OFFSET(1) NUMBITS(5) [],
        /// Enables the region
        ENABLE OFFSET(0) NUMBITS(1) []
    ]
];

/// State related to the real physical MPU.
///
/// There should only be one instantiation of this object as it represents
/// real hardware.
pub struct MPU<const NUM_REGIONS: usize, const MIN_REGION_SIZE: usize> {
    /// MMIO reference to MPU registers.
    registers: StaticRef<MpuRegisters>,
    /// Monotonically increasing counter for allocated regions, used
    /// to assign unique IDs to `CortexMConfig` instances.
    config_count: Cell<NonZeroUsize>,
    /// Optimization logic. This is used to indicate which application the MPU
    /// is currently configured for so that the MPU can skip updating when the
    /// kernel returns to the same app.
    hardware_is_configured_for: OptionalCell<NonZeroUsize>,
}

impl<const NUM_REGIONS: usize, const MIN_REGION_SIZE: usize> MPU<NUM_REGIONS, MIN_REGION_SIZE> {
    /// Create a new Cortex-M compatible MPU.
    ///
    /// This implements [`mpu::MPU`] for use with Tock processes.
    ///
    /// # Safety
    ///
    /// This struct implements [`mpu::MPU`] which is an unsafe trait that
    /// enforces Rust memory safety when userspace processes run. This
    /// implementation guarantees that it correctly implements that trait.
    /// However, callers must ensure this is a valid hardware MPU on their chip
    /// and that the hardware will correctly enforce the expected memory
    /// protection features.
    pub const unsafe fn new(registers: StaticRef<MpuRegisters>) -> Self {
        Self {
            registers,
            config_count: Cell::new(NonZeroUsize::MIN),
            hardware_is_configured_for: OptionalCell::empty(),
        }
    }

    // Function useful for boards where the bootloader sets up some
    // MPU configuration that conflicts with Tock's configuration:
    pub unsafe fn clear_mpu(&self) {
        self.registers.ctrl.write(Control::ENABLE::CLEAR);
    }
}

/// Per-process struct storing MPU configuration for cortex-m MPUs.
///
/// The cortex-m MPU has eight regions, all of which must be configured (though
/// unused regions may be configured as disabled). This struct caches the result
/// of region configuration calculation.
pub struct CortexMConfig<const NUM_REGIONS: usize> {
    /// Unique ID for this configuration, assigned from a
    /// monotonically increasing counter in the MPU struct.
    id: NonZeroUsize,
    /// The computed region configuration for this process.
    regions: [CortexMRegion; NUM_REGIONS],
    /// Has the configuration changed since the last time the this process
    /// configuration was written to hardware?
    is_dirty: Cell<bool>,
}

/// Records the index of the last region used for application RAM memory.
///
/// Regions 0-APP_MEMORY_REGION_MAX_NUM are used for application RAM. Regions
/// with indices above APP_MEMORY_REGION_MAX_NUM can be used for other MPU
/// needs.
const APP_MEMORY_REGION_MAX_NUM: usize = 1;

impl<const NUM_REGIONS: usize> fmt::Display for CortexMConfig<NUM_REGIONS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\r\n Cortex-M MPU")?;
        for (i, region) in self.regions.iter().enumerate() {
            if let Some(location) = region.location() {
                let access_bits = region.attributes().read(RegionAttributes::AP);
                let access_str = match access_bits {
                    0b000 => "NoAccess",
                    0b001 => "PrivilegedOnly",
                    0b010 => "UnprivilegedReadOnly",
                    0b011 => "ReadWrite",
                    0b100 => "Reserved",
                    0b101 => "PrivilegedOnlyReadOnly",
                    0b110 => "ReadOnly",
                    0b111 => "ReadOnlyAlias",
                    _ => "ERR",
                };
                let start = location.0 as usize;
                write!(
                    f,
                    "\
                     \r\n  Region {}: [{:#010X}:{:#010X}], length: {} bytes; {} ({:#x})",
                    i,
                    start,
                    start + location.1,
                    location.1,
                    access_str,
                    access_bits,
                )?;
                let subregion_bits = region.attributes().read(RegionAttributes::SRD);
                // Subregions divide the underlying block, which is often larger
                // than the logical region exposed to the process, so their
                // bounds have to come from the hardware encoding rather than
                // from `location`. The block is `2^(SIZE+1)` bytes based at
                // `ADDR << 5`, and holds eight subregions.
                let block_start =
                    (region.base_address().read(RegionBaseAddress::ADDR) as usize) << 5;
                let subregion_size =
                    1_usize << (region.attributes().read(RegionAttributes::SIZE) - 2);
                for j in 0..8 {
                    write!(
                        f,
                        "\
                         \r\n    Sub-region {}: [{:#010X}:{:#010X}], {}",
                        j,
                        block_start + j * subregion_size,
                        block_start + (j + 1) * subregion_size,
                        if (subregion_bits >> j) & 1 == 0 {
                            "Enabled"
                        } else {
                            "Disabled"
                        },
                    )?;
                }
            } else {
                write!(f, "\r\n  Region {}: Unused", i)?;
            }
        }
        write!(f, "\r\n")
    }
}

impl<const NUM_REGIONS: usize> CortexMConfig<NUM_REGIONS> {
    fn unused_region_number(&self) -> Option<usize> {
        for (number, region) in self.regions.iter().enumerate() {
            if number <= APP_MEMORY_REGION_MAX_NUM {
                continue;
            }
            if region.location().is_none() {
                return Some(number);
            }
        }
        None
    }
}

/// The geometry of a single Cortex-M MPU region.
///
/// The hardware can only express a region as a *block* whose size is a power of
/// two and whose base address is a multiple of that size. The block is divided
/// into exactly eight equally sized subregions, each of which can be
/// individually enabled. The logical region a process sees is therefore a
/// contiguous run of enabled subregions somewhere inside the block.
//#[derive(Copy, Clone)]
struct RegionGeometry {
    /// Start of the logical region (the first enabled subregion).
    start: usize,
    /// Length of the logical region.
    size: usize,
    /// Base address of the underlying block.
    block_start: usize,
    /// Size of the underlying block; always eight subregions.
    block_size: usize,
    /// Index of the first enabled subregion within the block.
    first_subregion: usize,
    /// Index of the last enabled subregion within the block.
    last_subregion: usize,
}

impl RegionGeometry {
    /// Find the smallest expressible region of at least `min_size` bytes that
    /// fits within `[window_start, window_end)`.
    ///
    /// Because every subregion in a block has the same size, a run of `count`
    /// subregions of `subregion_size` bytes can only be expressed when the run
    /// starts on a `subregion_size` boundary and does not cross the end of its
    /// block, that is when `index + count <= 8` for the index of the first
    /// enabled subregion. Rather than guess a subregion size from the alignment
    /// of the window (which rejects layouts the hardware can represent), we
    /// enumerate every `(subregion_size, count)` pair the hardware can encode,
    /// compute the earliest start address each admits, and keep the smallest
    /// region found. Ties are broken towards the lowest start address.
    fn fit(window_start: usize, window_end: usize, min_size: usize) -> Option<Self> {
        let window_size = window_end.checked_sub(window_start)?;
        let mut best: Option<Self> = None;

        let mut subregion_size = CORTEXM_MIN_REGION_SIZE;
        loop {
            if subregion_size > window_size {
                break;
            }
            // Blocks smaller than eight times the minimum subregion size cannot
            // use subregions at all, so the block is always eight subregions.
            let Some(block_size) = subregion_size.checked_mul(8) else {
                break;
            };

            for count in 1..=8 {
                // Cannot overflow: `subregion_size * 8` is known to fit.
                let size = subregion_size * count;
                if size > window_size {
                    // `size` only grows with `count`.
                    break;
                }
                if size < min_size {
                    continue;
                }

                // Earliest subregion-aligned address at or after the window
                // start, advanced to the next block if a run of `count`
                // subregions would overrun the block it lands in.
                let Some(mut start) = window_start
                    .div_ceil(subregion_size)
                    .checked_mul(subregion_size)
                else {
                    continue;
                };
                let index = (start / subregion_size) % 8;
                if index + count > 8 {
                    let Some(next_block) = start.checked_add((8 - index) * subregion_size) else {
                        continue;
                    };
                    start = next_block;
                }
                let index = (start / subregion_size) % 8;

                if start.checked_add(size).is_none_or(|end| end > window_end) {
                    continue;
                }

                best = Some(if let Some(b) = best && (size, start) >= (b.size, b.start) {
                    b
                } else {
                    RegionGeometry {
                        start,
                        size,
                        block_start: start - (start % block_size),
                        block_size,
                        first_subregion: index,
                        last_subregion: index + count - 1,
                    }
                });
            }

            let Some(next) = subregion_size.checked_mul(2) else {
                break;
            };
            subregion_size = next;
        }

        best
    }
}

/// Struct storing configuration for a Cortex-M MPU region.
#[derive(Copy, Clone)]
pub struct CortexMRegion {
    location: Option<(*const u8, usize)>,
    base_address: FieldValue<u32, RegionBaseAddress::Register>,
    attributes: FieldValue<u32, RegionAttributes::Register>,
}

impl PartialEq<mpu::Region> for CortexMRegion {
    fn eq(&self, other: &mpu::Region) -> bool {
        self.location.is_some_and(|(addr, size)| {
            core::ptr::eq(addr, other.start_address()) && size == other.size()
        })
    }
}

impl CortexMRegion {
    fn new(
        logical_start: *const u8,
        logical_size: usize,
        region_start: *const u8,
        region_size: usize,
        region_num: usize,
        subregions: Option<(usize, usize)>,
        permissions: mpu::Permissions,
    ) -> Option<CortexMRegion> {
        // Logical size must be above minimum size for cortexM MPU regions and
        // and less than the size of the underlying physical region
        if logical_size < CORTEXM_MIN_REGION_SIZE || region_size < logical_size {
            return None;
        }

        // Determine access and execute permissions
        let (access, execute) = match permissions {
            mpu::Permissions::ReadWriteExecute => (
                RegionAttributes::AP::ReadWrite,
                RegionAttributes::XN::Enable,
            ),
            mpu::Permissions::ReadWriteOnly => (
                RegionAttributes::AP::ReadWrite,
                RegionAttributes::XN::Disable,
            ),
            mpu::Permissions::ReadExecuteOnly => (
                RegionAttributes::AP::UnprivilegedReadOnly,
                RegionAttributes::XN::Enable,
            ),
            mpu::Permissions::ReadOnly => (
                RegionAttributes::AP::UnprivilegedReadOnly,
                RegionAttributes::XN::Disable,
            ),
            mpu::Permissions::ExecuteOnly => (
                RegionAttributes::AP::PrivilegedOnly,
                RegionAttributes::XN::Enable,
            ),
        };

        // Base address register
        let base_address = RegionBaseAddress::ADDR.val((region_start as u32) >> 5)
            + RegionBaseAddress::VALID::UseRBAR
            + RegionBaseAddress::REGION.val(region_num as u32);

        let size_value = math::log_base_two(region_size as u32) - 1;

        // Attributes register
        let mut attributes = RegionAttributes::ENABLE::SET
            + RegionAttributes::SIZE.val(size_value)
            + access
            + execute;

        // If using subregions, add a subregion mask. The mask is a 8-bit
        // bitfield where `0` indicates that the corresponding subregion is enabled.
        // To compute the mask, we start with all subregions disabled and enable
        // the ones in the inclusive range [min_subregion, max_subregion].
        if let Some((min_subregion, max_subregion)) = subregions {
            let mask = (min_subregion..=max_subregion).fold(u8::MAX, |res, i| {
                // Enable subregions bit by bit (1 ^ 1 == 0)
                res ^ (1 << i)
            });
            attributes += RegionAttributes::SRD.val(mask as u32);
        }

        Some(CortexMRegion {
            location: Some((logical_start, logical_size)),
            base_address,
            attributes,
        })
    }

    fn empty(region_num: usize) -> CortexMRegion {
        CortexMRegion {
            location: None,
            base_address: RegionBaseAddress::VALID::UseRBAR
                + RegionBaseAddress::REGION.val(region_num as u32),
            attributes: RegionAttributes::ENABLE::CLEAR,
        }
    }

    fn location(&self) -> Option<(*const u8, usize)> {
        self.location
    }

    fn base_address(&self) -> FieldValue<u32, RegionBaseAddress::Register> {
        self.base_address
    }

    fn attributes(&self) -> FieldValue<u32, RegionAttributes::Register> {
        self.attributes
    }

    fn overlaps(&self, other_start: *const u8, other_size: usize) -> bool {
        let other_start = other_start as usize;
        let other_end = other_start + other_size;

        let (region_start, region_end) = match self.location {
            Some((region_start, region_size)) => {
                let region_start = region_start as usize;
                let region_end = region_start + region_size;
                (region_start, region_end)
            }
            None => return false,
        };

        region_start < other_end && other_start < region_end
    }
}

// `MPU` is an unsafe trait, and with this implementation we guarantee
// that we adhere to the semantics documented on that trait and its
// associated types and methods.
unsafe impl<const NUM_REGIONS: usize, const MIN_REGION_SIZE: usize> mpu::MPU
    for MPU<NUM_REGIONS, MIN_REGION_SIZE>
{
    type MpuConfig = CortexMConfig<NUM_REGIONS>;

    fn enable_app_mpu(&self) {
        // Enable the MPU, disable it during HardFault/NMI handlers, and allow
        // privileged code access to all unprotected memory.
        self.registers
            .ctrl
            .write(Control::ENABLE::SET + Control::HFNMIENA::CLEAR + Control::PRIVDEFENA::SET);
    }

    unsafe fn disable_app_mpu(&self) {
        // The MPU is not enabled for privileged mode, so we don't have to do
        // anything
        self.registers.ctrl.write(Control::ENABLE::CLEAR);
    }

    fn number_total_regions(&self) -> usize {
        self.registers.mpu_type.read(Type::DREGION) as usize
    }

    fn new_config(&self) -> Option<Self::MpuConfig> {
        let id = self.config_count.get();
        self.config_count.set(id.checked_add(1)?);

        // Allocate the regions with index `0` first, then use `reset_config` to
        // write the properly-indexed `CortexMRegion`s:
        let mut ret = CortexMConfig {
            id,
            regions: [CortexMRegion::empty(0); NUM_REGIONS],
            is_dirty: Cell::new(true),
        };

        self.reset_config(&mut ret);

        Some(ret)
    }

    fn reset_config(&self, config: &mut Self::MpuConfig) {
        for i in 0..NUM_REGIONS {
            config.regions[i] = CortexMRegion::empty(i);
        }

        config.is_dirty.set(true);
    }

    fn allocate_region(
        &self,
        unallocated_memory_start: *const u8,
        unallocated_memory_size: usize,
        min_region_size: usize,
        permissions: mpu::Permissions,
        config: &mut Self::MpuConfig,
    ) -> Option<mpu::Region> {
        // Check that no previously allocated regions overlap the unallocated memory.
        for region in config.regions.iter() {
            if region.overlaps(unallocated_memory_start, unallocated_memory_size) {
                return None;
            }
        }

        let region_num = config.unused_region_number()?;

        // Region start always has to align to minimum region size bytes, and
        // regions must be at least minimum region size bytes.
        let window_start = (unallocated_memory_start as usize).next_multiple_of(MIN_REGION_SIZE);
        let window_end =
            (unallocated_memory_start as usize).checked_add(unallocated_memory_size)?;
        let min_size = cmp::max(min_region_size, MIN_REGION_SIZE);

        let geometry = RegionGeometry::fit(window_start, window_end, min_size)?;

        let region = CortexMRegion::new(
            geometry.start as *const u8,
            geometry.size,
            geometry.block_start as *const u8,
            geometry.block_size,
            region_num,
            Some((geometry.first_subregion, geometry.last_subregion)),
            permissions,
        )?;

        config.regions[region_num] = region;
        config.is_dirty.set(true);

        Some(mpu::Region::new(geometry.start as *const u8, geometry.size))
    }

    fn remove_memory_region(
        &self,
        region: mpu::Region,
        config: &mut Self::MpuConfig,
    ) -> Result<(), ()> {
        let (idx, _r) = config
            .regions
            .iter()
            .enumerate()
            .find(|(_idx, r)| **r == region)
            .ok_or(())?;

        if idx <= APP_MEMORY_REGION_MAX_NUM {
            return Err(());
        }

        config.regions[idx] = CortexMRegion::empty(idx);
        config.is_dirty.set(true);

        Ok(())
    }

    // When allocating memory for apps, we use two regions, each a power of two
    // in size. By using two regions we halve their size, and also halve their
    // alignment restrictions.
    fn allocate_app_memory_region(
        &self,
        unallocated_memory_start: *const u8,
        unallocated_memory_size: usize,
        min_memory_size: usize,
        initial_app_memory_size: usize,
        initial_kernel_memory_size: usize,
        permissions: mpu::Permissions,
        config: &mut Self::MpuConfig,
    ) -> Option<(*const u8, usize)> {
        // Check that no previously allocated regions overlap the unallocated
        // memory.
        for region in config.regions.iter() {
            if region.overlaps(unallocated_memory_start, unallocated_memory_size) {
                return None;
            }
        }

        // Make sure there is enough memory for app memory and kernel memory.
        let memory_size = cmp::max(
            min_memory_size,
            initial_app_memory_size + initial_kernel_memory_size,
        );

        // Size must be a power of two, so:
        // https://www.youtube.com/watch?v=ovo6zwv6DX4.
        let mut memory_size_po2 = (memory_size as u32).next_power_of_two() as usize;
        let exponent = math::log_base_two(memory_size_po2 as u32);

        // Check for compliance with the constraints of the MPU.
        if exponent < 9 {
            // Region sizes must be 256 bytes or larger to support subregions.
            // Since we are using two regions, and each must be at least 256
            // bytes, we need the entire memory region to be at least 512 bytes.
            memory_size_po2 = 512;
        } else if exponent > 32 {
            // Region sizes must be 4GB or smaller.
            return None;
        }

        // Region size is the actual size the MPU region will be set to, and is
        // half of the total power of two size we are allocating to the app.
        let mut region_size = memory_size_po2 / 2;

        // The region should start as close as possible to the start of the
        // unallocated memory.
        let mut region_start = unallocated_memory_start as usize;

        // If the start and length don't align, move region up until it does.
        region_start = region_start.next_multiple_of(region_size);

        // We allocate two MPU regions exactly over the process memory block,
        // and we disable subregions at the end of this region to disallow
        // access to the memory past the app break. As the app break later
        // increases, we will be able to linearly grow the logical region
        // covering app-owned memory by enabling more and more subregions. The
        // Cortex-M MPU supports 8 subregions per region, so the size of this
        // logical region is always a multiple of a sixteenth of the MPU region
        // length.

        // Determine the number of subregions to enable.
        // Want `round_up(app_memory_size / subregion_size)`.
        let mut num_enabled_subregions = initial_app_memory_size * 8 / region_size + 1;

        let subregion_size = region_size / 8;

        // Calculates the end address of the enabled subregions and the initial
        // kernel memory break.
        let subregions_enabled_end = region_start + num_enabled_subregions * subregion_size;
        let kernel_memory_break = region_start + memory_size_po2 - initial_kernel_memory_size;

        // If the last subregion covering app-owned memory overlaps the start of
        // kernel-owned memory, we make the entire process memory block twice as
        // big so there is plenty of space between app-owned and kernel-owned
        // memory.
        if subregions_enabled_end > kernel_memory_break {
            memory_size_po2 *= 2;
            region_size *= 2;

            region_start = region_start.next_multiple_of(region_size);

            num_enabled_subregions = initial_app_memory_size * 8 / region_size + 1;
        }

        // Make sure the region fits in the unallocated memory.
        if region_start + memory_size_po2
            > (unallocated_memory_start as usize) + unallocated_memory_size
        {
            return None;
        }

        // Get the number of subregions enabled in each of the two MPU regions.
        let num_enabled_subregions0 = cmp::min(num_enabled_subregions, 8);
        let num_enabled_subregions1 = num_enabled_subregions.saturating_sub(8);

        let region0 = CortexMRegion::new(
            region_start as *const u8,
            region_size,
            region_start as *const u8,
            region_size,
            0,
            Some((0, num_enabled_subregions0 - 1)),
            permissions,
        )?;

        // We cannot have a completely unused MPU region
        let region1 = if num_enabled_subregions1 == 0 {
            CortexMRegion::empty(1)
        } else {
            CortexMRegion::new(
                (region_start + region_size) as *const u8,
                region_size,
                (region_start + region_size) as *const u8,
                region_size,
                1,
                Some((0, num_enabled_subregions1 - 1)),
                permissions,
            )?
        };

        config.regions[0] = region0;
        config.regions[1] = region1;
        config.is_dirty.set(true);

        Some((region_start as *const u8, memory_size_po2))
    }

    fn update_app_memory_region(
        &self,
        app_memory_break: *const u8,
        kernel_memory_break: *const u8,
        permissions: mpu::Permissions,
        config: &mut Self::MpuConfig,
    ) -> Result<(), ()> {
        // Get first region, or error if the process tried to update app memory
        // MPU region before it was created.
        let (region_start_ptr, region_size) = config.regions[0].location().ok_or(())?;
        let region_start = region_start_ptr as usize;

        let app_memory_break = app_memory_break as usize;
        let kernel_memory_break = kernel_memory_break as usize;

        // Out of memory
        if app_memory_break > kernel_memory_break {
            return Err(());
        }

        // Number of bytes the process wants access to.
        let app_memory_size = app_memory_break - region_start;

        // There are eight subregions for every region in the Cortex-M3/4 MPU.
        let subregion_size = region_size / 8;

        // Determine the number of subregions to enable.
        // Want `round_up(app_memory_size / subregion_size)`.
        let num_enabled_subregions = app_memory_size.div_ceil(subregion_size);

        let subregions_enabled_end = region_start + subregion_size * num_enabled_subregions;

        // If we can no longer cover app memory with an MPU region without
        // overlapping kernel memory, we fail.
        if subregions_enabled_end > kernel_memory_break {
            return Err(());
        }

        // Get the number of subregions enabled in each of the two MPU regions.
        let num_enabled_subregions0 = cmp::min(num_enabled_subregions, 8);
        let num_enabled_subregions1 = num_enabled_subregions.saturating_sub(8);

        let region0 = CortexMRegion::new(
            region_start as *const u8,
            region_size,
            region_start as *const u8,
            region_size,
            0,
            Some((0, num_enabled_subregions0 - 1)),
            permissions,
        )
        .ok_or(())?;

        let region1 = if num_enabled_subregions1 == 0 {
            CortexMRegion::empty(1)
        } else {
            CortexMRegion::new(
                (region_start + region_size) as *const u8,
                region_size,
                (region_start + region_size) as *const u8,
                region_size,
                1,
                Some((0, num_enabled_subregions1 - 1)),
                permissions,
            )
            .ok_or(())?
        };

        config.regions[0] = region0;
        config.regions[1] = region1;
        config.is_dirty.set(true);

        Ok(())
    }

    unsafe fn configure_mpu(&self, config: &Self::MpuConfig) {
        // If the hardware is already configured for this app and the app's MPU
        // configuration has not changed, then skip the hardware update.
        if !self.hardware_is_configured_for.contains(&config.id) || config.is_dirty.get() {
            // Set MPU regions
            for region in config.regions.iter() {
                self.registers.rbar.write(region.base_address());
                self.registers.rasr.write(region.attributes());
            }
            self.hardware_is_configured_for.set(config.id);
            config.is_dirty.set(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::platform::mpu::MPU as _;

    /// Construct an `MPU` for testing.
    ///
    /// Region allocation is pure arithmetic over the config and never touches
    /// the MMIO registers, but building an `MPU` still needs a `StaticRef` that
    /// points at correctly aligned, live memory.
    #[repr(align(4))]
    struct FakeRegisters(#[allow(dead_code)] [u8; core::mem::size_of::<MpuRegisters>()]);
    static FAKE_REGISTERS: FakeRegisters = FakeRegisters([0; core::mem::size_of::<MpuRegisters>()]);

    fn mpu<const NUM_REGIONS: usize, const MIN_REGION_SIZE: usize>()
    -> MPU<NUM_REGIONS, MIN_REGION_SIZE> {
        let ptr = core::ptr::addr_of!(FAKE_REGISTERS).cast::<MpuRegisters>();
        // SAFETY: the registers are never dereferenced by the methods under
        // test, and the pointer is aligned and points at live memory.
        unsafe { MPU::new(StaticRef::new(ptr)) }
    }

    /// Decode what was actually programmed into a hardware region: the block
    /// base, the block size, and the subregion-disable mask.
    fn decode(region: &CortexMRegion) -> (usize, usize, u8) {
        let rbar = region.base_address().value;
        let rasr = region.attributes().value;
        assert_eq!(rasr & 1, 1, "region should be enabled");
        let base = (rbar & !0x1f) as usize;
        let block_size = 1_usize << (((rasr >> 1) & 0x1f) + 1);
        let srd = ((rasr >> 8) & 0xff) as u8;
        (base, block_size, srd)
    }

    /// The exact range of bytes a programmed region grants access to.
    ///
    /// Panics if the enabled subregions are not a single contiguous run, which
    /// would mean the region grants access to a gap it should not.
    fn granted(region: &CortexMRegion) -> (usize, usize) {
        let (base, block_size, srd) = decode(region);
        let granule = block_size / 8;
        let (mut lo, mut hi) = (None, 0);
        for i in 0..8 {
            if (srd >> i) & 1 == 0 {
                let start = base + i * granule;
                match lo {
                    None => lo = Some(start),
                    Some(_) => assert_eq!(hi, start, "enabled subregions must be contiguous"),
                }
                hi = start + granule;
            }
        }
        (lo.expect("at least one subregion must be enabled"), hi)
    }

    /// Independent model of what one ARMv7-M region can express.
    ///
    /// Derived from the hardware rules rather than from the allocator: a block
    /// is a power-of-two size, aligned to itself, holding eight subregions;
    /// blocks below 256 bytes cannot use subregions at all.
    fn expressible(start: usize, size: usize) -> bool {
        let with_subregions = (5..=24).any(|j| {
            let g = 1_usize << j;
            start.is_multiple_of(g)
                && size.is_multiple_of(g)
                && size / g >= 1
                && ((start / g) % 8) + size / g <= 8
        });
        let without_subregions = matches!(size, 32 | 64 | 128) && start.is_multiple_of(size);
        with_subregions || without_subregions
    }

    /// The smallest region of at least `min_size` bytes expressible inside
    /// `[window_start, window_end)`, found by exhaustive search.
    fn brute_force(window_start: usize, window_end: usize, min_size: usize) -> Option<usize> {
        let mut best = None;
        let mut start = window_start;
        while start < window_end {
            let mut size = min_size.next_multiple_of(CORTEXM_MIN_REGION_SIZE);
            while start + size <= window_end {
                if expressible(start, size) && best.is_none_or(|b| size < b) {
                    best = Some(size);
                }
                size += CORTEXM_MIN_REGION_SIZE;
            }
            start += CORTEXM_MIN_REGION_SIZE;
        }
        best
    }

    /// The region geometry the allocator computed before Stage 1a, kept here as
    /// a reference so we can assert the new allocator never rejects a layout
    /// the old one accepted.
    fn legacy_geometry(
        unallocated_memory_start: usize,
        unallocated_memory_size: usize,
        min_region_size: usize,
        min_region_size_const: usize,
    ) -> Option<(usize, usize)> {
        let mut start = unallocated_memory_start.next_multiple_of(min_region_size_const);
        let mut size = core::cmp::max(min_region_size, min_region_size_const);

        if size.count_ones() > 1 || !start.is_multiple_of(size) {
            let subregion_size = {
                let tz = start.trailing_zeros();
                if tz < 32 {
                    1_usize << tz
                } else {
                    core::cmp::max((size as u32).next_power_of_two() as usize, 256) / 8
                }
            };
            let underlying_region_size = subregion_size * 8;
            let underlying_region_start = start - (start % underlying_region_size);
            size = size.next_multiple_of(subregion_size);

            if subregion_size >= 32
                && underlying_region_start + underlying_region_size >= start + size
            {
                // covered by subregions
            } else {
                size = (size as u32).next_power_of_two() as usize;
                start += size - (start % size);
            }
        }

        (start + size <= unallocated_memory_start + unallocated_memory_size)
            .then_some((start, size))
    }

    fn alloc<const N: usize, const MIN: usize>(
        m: &MPU<N, MIN>,
        config: &mut CortexMConfig<N>,
        start: usize,
        window: usize,
        min_size: usize,
    ) -> Option<mpu::Region> {
        m.allocate_region(
            start as *const u8,
            window,
            min_size,
            mpu::Permissions::ReadExecuteOnly,
            config,
        )
    }

    // ---- property tests -------------------------------------------------

    /// Whenever a single region can cover the request, the allocator finds one,
    /// and the one it finds is the smallest such region.
    #[test]
    fn allocator_is_complete_and_minimal() {
        let m = mpu::<8, 32>();
        let mut checked = 0;
        for window_start in (0x1000..0x1000 + 2048).step_by(32) {
            for window in (32..2048).step_by(96) {
                for min_size in (32..1024).step_by(160) {
                    let mut config = m.new_config().unwrap();
                    let got = alloc(&m, &mut config, window_start, window, min_size);
                    let want = brute_force(window_start, window_start + window, min_size);
                    assert_eq!(
                        got.map(|r| r.size()),
                        want,
                        "window {window_start:#x}+{window}, min_size {min_size}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 1000);
    }

    /// Every allocation grants exactly the range it reports back.
    ///
    /// No more and no less. An off-by-one in the subregion mask would hand a
    /// process bytes belonging to its neighbour, so this is the invariant that
    /// actually matters.
    #[test]
    fn allocation_grants_exactly_the_reported_range() {
        let m = mpu::<8, 32>();
        for window_start in [0x0, 0x20, 0x1000, 0x8020, 0x7_0000, 0x1234 * 32] {
            for window in (32..8192).step_by(64) {
                for min_size in (32..4096).step_by(224) {
                    let mut config = m.new_config().unwrap();
                    let Some(region) = alloc(&m, &mut config, window_start, window, min_size)
                    else {
                        continue;
                    };
                    let start = region.start_address() as usize;

                    assert!(region.size() >= min_size, "granted less than requested");
                    assert!(start >= window_start, "region starts before the window");
                    assert!(
                        start + region.size() <= window_start + window,
                        "region runs past the window"
                    );
                    assert_eq!(
                        granted(&config.regions[2]),
                        (start, start + region.size()),
                        "hardware grants a different range than was reported"
                    );
                }
            }
        }
    }

    /// Stage 1a must only ever widen what loads: anything the previous
    /// allocator accepted must still be accepted.
    #[test]
    fn no_regression_against_previous_allocator() {
        let m = mpu::<8, 32>();
        let mut legacy_ok = 0;
        for window_start in (0x0..0x4000).step_by(160) {
            for window in (32..4096).step_by(96) {
                for min_size in (32..2048).step_by(160) {
                    let Some((legacy_start, legacy_size)) =
                        legacy_geometry(window_start, window, min_size, 32)
                    else {
                        continue;
                    };
                    legacy_ok += 1;
                    let mut config = m.new_config().unwrap();
                    let got = alloc(&m, &mut config, window_start, window, min_size)
                        .unwrap_or_else(|| {
                            panic!(
                                "regression: legacy allocator produced {legacy_start:#x}+\
                                 {legacy_size} for window {window_start:#x}+{window} \
                                 min_size {min_size}, new allocator refused"
                            )
                        });
                    assert!(
                        got.size() <= legacy_size,
                        "new allocator granted more than the legacy one"
                    );
                }
            }
        }
        assert!(
            legacy_ok > 500,
            "legacy reference never succeeded; test is vacuous"
        );
    }

    // ---- specific behaviours --------------------------------------------

    /// A 96 KiB process binary at a 64 KiB-aligned address.
    ///
    /// Three subregions of 32 KiB express this exactly, but the previous
    /// allocator derived the subregion size solely from the start address,
    /// rounded 96 KiB up to 128 KiB, overran the window and gave up.
    #[test]
    fn flash_region_with_odd_part_three() {
        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        let (start, len) = (0x1_0000, 96 * 1024);

        assert!(
            legacy_geometry(start, len, len, 32).is_none(),
            "should regress"
        );

        let region = alloc(&m, &mut config, start, len, len).expect("should allocate");
        assert_eq!(region.start_address() as usize, start);
        assert_eq!(region.size(), len);
        assert_eq!(granted(&config.regions[2]), (start, start + len));

        let (base, block_size, srd) = decode(&config.regions[2]);
        assert_eq!((base, block_size), (0x0, 256 * 1024));
        // 96 KiB starting 64 KiB into a 256 KiB block of 32 KiB subregions is
        // subregions 2, 3 and 4; the rest are disabled.
        assert_eq!(srd, 0b1110_0011, "subregions 2..=4 of a 256 KiB block");
    }

    /// A small IPC-style buffer inside a large, highly aligned window.
    ///
    /// The previous allocator picked a subregion size from the window's
    /// alignment, which for a 512 MiB-aligned base meant trying to hand out
    /// 512 MiB.
    #[test]
    fn small_buffer_in_large_aligned_window() {
        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        let (base, window) = (0x2000_0000, 32 * 1024);

        assert!(
            legacy_geometry(base, window, 1000, 32).is_none(),
            "should regress"
        );

        let region = alloc(&m, &mut config, base, window, 1000).expect("should allocate");
        assert_eq!(region.start_address() as usize, base);
        assert_eq!(region.size(), 1024, "smallest expressible size >= 1000");
        assert_eq!(granted(&config.regions[2]), (base, base + 1024));
    }

    /// A naturally aligned power-of-two region still programs as one block with
    /// every subregion enabled.
    #[test]
    fn naturally_aligned_power_of_two_is_unchanged() {
        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        let len = 128 * 1024;
        let region = alloc(&m, &mut config, 0x2_0000, len, len).expect("should allocate");

        assert_eq!(region.size(), len);
        let (base, block_size, srd) = decode(&config.regions[2]);
        assert_eq!((base, block_size, srd), (0x2_0000, len, 0));
    }

    /// 128 KiB at 0x7_0000 straddles a block boundary no single region can
    /// cross, so it still fails. This is the case Stage 1b exists to fix;
    /// if this ever starts passing, the two-region work landed.
    #[test]
    fn single_region_still_cannot_straddle_a_block_boundary() {
        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        let len = 128 * 1024;
        assert!(alloc(&m, &mut config, 0x7_0000, len, len).is_none());
        assert_eq!(brute_force(0x7_0000, 0x7_0000 + len, len), None);
    }

    /// The Cortex-M0+ start-alignment floor is honoured.
    #[test]
    fn respects_the_larger_minimum_region_size() {
        let m = mpu::<8, 256>();
        let mut config = m.new_config().unwrap();
        let region = alloc(&m, &mut config, 0x1020, 4096, 64).expect("should allocate");
        assert_eq!(region.start_address() as usize % 256, 0);
        assert!(region.size() >= 256);
    }

    #[test]
    fn rejects_requests_that_cannot_fit() {
        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        assert!(alloc(&m, &mut config, 0x1000, 64, 128).is_none());
        assert!(alloc(&m, &mut config, 0x1000, 0, 32).is_none());
    }

    // ---- Display ---------------------------------------------------------

    struct Sink {
        buf: [u8; 16384],
        len: usize,
    }

    impl Sink {
        fn new() -> Self {
            Sink {
                buf: [0; 16384],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl fmt::Write for Sink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let b = s.as_bytes();
            let n = core::cmp::min(b.len(), self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
            self.len += n;
            Ok(())
        }
    }

    /// Subregion bounds are a property of the underlying block.
    ///
    /// The block is often larger than the logical region, so printing subregion
    /// bounds relative to the logical region made the debug output wrong
    /// whenever subregions were in use.
    #[test]
    fn display_reports_subregions_of_the_block() {
        use fmt::Write;

        let m = mpu::<8, 32>();
        let mut config = m.new_config().unwrap();
        let (start, len) = (0x1_0000, 96 * 1024);
        alloc(&m, &mut config, start, len, len).unwrap();

        let (base, block_size, _) = decode(&config.regions[2]);
        assert_ne!(base, start, "test only meaningful when the block is offset");

        let mut printed = Sink::new();
        write!(printed, "{}", config).unwrap();

        let mut needle = Sink::new();
        write!(
            needle,
            "Sub-region 0: [{:#010X}:{:#010X}]",
            base,
            base + block_size / 8
        )
        .unwrap();

        assert!(
            printed.as_str().contains(needle.as_str()),
            "expected {:?} in:\n{}",
            needle.as_str(),
            printed.as_str()
        );
    }
}
