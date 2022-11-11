//! Provides userspace control of firmware protection on a board.
//!
//! This allows an application to enable firware readout protection,
//! disabling JTAG interface and other ways to read/tamper the firmware.
//! Of course, outside of a hardware bug, once set, the only way to enable
//! programming/debugging is by fully erasing the flash.
//!
//! Usage
//! -----
//!
//! ```rust
//! # use kernel::static_init;
//!
//! let crp = static_init!(
//!     capsules::firmware_protection::FirmwareProtection,
//!     capsules::firmware_protection::FirmwareProtection::new(
//!         nrf52840::uicr::Uicr,
//!         board_kernel.create_grant(&grant_cap),
//!     );
//! ```
//!
//! Syscall Interface
//! -----------------
//!
//! - Stability: 0 - Draft
//!
//! ### Command
//!
//! Enable code readout protection on the current board.
//!
//! #### `command_num`
//!
//! - `0`: Driver check.
//! - `1`: Get current firmware readout protection (aka CRP) state.
//! - `2`: Set current firmware readout protection (aka CRP) state.
//!

use kernel::hil;
use kernel::{AppId, Callback, Driver, Grant, ReturnCode};

/// Syscall driver number.
use crate::driver;
pub const DRIVER_NUM: usize = driver::NUM::FirmwareProtection as usize;

pub struct FirmwareProtection<C: hil::firmware_protection::FirmwareProtection> {
    crp_unit: C,
    apps: Grant<Option<Callback>>,
}

impl<C: hil::firmware_protection::FirmwareProtection> FirmwareProtection<C> {
    pub fn new(crp_unit: C, apps: Grant<Option<Callback>>) -> Self {
        Self { crp_unit, apps }
    }
}

impl<C: hil::firmware_protection::FirmwareProtection> Driver for FirmwareProtection<C> {
    ///
    /// ### Command numbers
    ///
    ///   * `0`: Returns non-zero to indicate the driver is present.
    ///   * `1`: Gets firmware protection state.
    ///   * `2`: Sets firmware protection state.
    fn command(&self, command_num: usize, data: usize, _: usize, appid: AppId) -> ReturnCode {
        match command_num {
            // return if driver is available
            0 => ReturnCode::SUCCESS,

            1 => self
                .apps
                .enter(appid, |_, _| ReturnCode::SuccessWithValue {
                    value: self.crp_unit.get_protection() as usize,
                })
                .unwrap_or_else(|err| err.into()),

            // sets firmware protection
            2 => self
                .apps
                .enter(appid, |_, _| self.crp_unit.set_protection(data.into()))
                .unwrap_or_else(|err| err.into()),

            // default
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}
