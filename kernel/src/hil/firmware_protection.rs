//! Interface for Firmware Protection, also called Code Readout Protection.

use crate::returncode::ReturnCode;

#[derive(PartialOrd, PartialEq)]
pub enum ProtectionLevel {
    /// Unsupported feature
    Unknown = 0,
    /// This should be the factory default for the chip.
    NoProtection = 1,
    /// At this level, only JTAG/SWD are disabled but other debugging
    /// features may still be enabled.
    JtagDisabled = 2,
    /// This is the maximum level of protection the chip supports.
    /// At this level, JTAG and all other features are expected to be
    /// disabled and only a full chip erase may allow to recover from
    /// that state.
    FullyLocked = 0xff,
}

impl From<usize> for ProtectionLevel {
    fn from(value: usize) -> Self {
        match value {
            1 => ProtectionLevel::NoProtection,
            2 => ProtectionLevel::JtagDisabled,
            0xff => ProtectionLevel::FullyLocked,
            _ => ProtectionLevel::Unknown,
        }
    }
}

pub trait FirmwareProtection {
    /// Gets the current firmware protection level.
    /// This doesn't fail and always returns a value.
    fn get_protection(&self) -> ProtectionLevel;

    /// Sets the firmware protection level.
    /// There are four valid return values:
    ///   - SUCCESS: protection level has been set to `level`
    ///   - FAIL: something went wrong while setting the protection
    ///     level and the effective protection level is not the one
    ///     that was requested.
    ///   - EALREADY: the requested protection level is already the
    ///     level that is set.
    ///   - EINVAL: unsupported protection level or the requested
    ///     protection level is lower than the currently set one.
    fn set_protection(&self, level: ProtectionLevel) -> ReturnCode;
}
