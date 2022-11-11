//! Component for firmware protection syscall interface.
//!
//! This provides one Component, `FirmwareProtectionComponent`, which implements a
//! userspace syscall interface to enable the code readout protection.
//!
//! Usage
//! -----
//! ```rust
//! let crp = components::firmware_protection::FirmwareProtectionComponent::new(
//!     board_kernel,
//!     nrf52840::uicr::Uicr::new()
//! )
//! .finalize(
//!     components::firmware_protection_component_helper!(uicr));
//! ```

use core::mem::MaybeUninit;

use capsules::firmware_protection;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;
use kernel::static_init_half;

// Setup static space for the objects.
#[macro_export]
macro_rules! firmware_protection_component_helper {
    ($C:ty) => {{
        use capsules::firmware_protection;
        use core::mem::MaybeUninit;
        static mut BUF: MaybeUninit<firmware_protection::FirmwareProtection<$C>> =
            MaybeUninit::uninit();
        &mut BUF
    };};
}

pub struct FirmwareProtectionComponent<C: hil::firmware_protection::FirmwareProtection> {
    board_kernel: &'static kernel::Kernel,
    crp: C,
}

impl<C: 'static + hil::firmware_protection::FirmwareProtection> FirmwareProtectionComponent<C> {
    pub fn new(board_kernel: &'static kernel::Kernel, crp: C) -> FirmwareProtectionComponent<C> {
        FirmwareProtectionComponent {
            board_kernel: board_kernel,
            crp: crp,
        }
    }
}

impl<C: 'static + hil::firmware_protection::FirmwareProtection> Component
    for FirmwareProtectionComponent<C>
{
    type StaticInput = &'static mut MaybeUninit<firmware_protection::FirmwareProtection<C>>;
    type Output = &'static firmware_protection::FirmwareProtection<C>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        static_init_half!(
            static_buffer,
            firmware_protection::FirmwareProtection<C>,
            firmware_protection::FirmwareProtection::new(
                self.crp,
                self.board_kernel.create_grant(&grant_cap),
            )
        )
    }
}
