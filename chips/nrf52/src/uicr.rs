//! User information configuration registers

use enum_primitive::cast::FromPrimitive;
use hil::firmware_protection::ProtectionLevel;
use kernel::common::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::common::StaticRef;
use kernel::hil;
use kernel::ReturnCode;

use crate::gpio::Pin;
use crate::nvmc;

const UICR_BASE: StaticRef<UicrRegisters> =
    unsafe { StaticRef::new(0x10001000 as *const UicrRegisters) };

register_structs! {
    UicrRegisters {
        (0x000 => _reserved1),
        /// Reserved for Nordic firmware design
        (0x014 => nrffw: [ReadWrite<u32>; 13]),
        (0x048 => _reserved2),
        /// Reserved for Nordic hardware design
        (0x050 => nrfhw: [ReadWrite<u32>; 12]),
        /// Reserved for customer
        (0x080 => customer: [ReadWrite<u32>; 32]),
        (0x100 => _reserved3),
        /// Mapping of the nRESET function (see POWER chapter for details)
        (0x200 => pselreset0: ReadWrite<u32, Pselreset::Register>),
        /// Mapping of the nRESET function (see POWER chapter for details)
        (0x204 => pselreset1: ReadWrite<u32, Pselreset::Register>),
        /// Access Port protection
        (0x208 => approtect: ReadWrite<u32, ApProtect::Register>),
        /// Setting of pins dedicated to NFC functionality: NFC antenna or GPIO
        /// - Address: 0x20c - 0x210
        (0x20c => nfcpins: ReadWrite<u32, NfcPins::Register>),
        (0x210 => debugctrl: ReadWrite<u32, DebugControl::Register>),
        (0x214 => _reserved4),
        /// External circuitry to be supplied from VDD pin.
        (0x300 => extsupply: ReadWrite<u32, ExtSupply::Register>),
        /// GPIO reference voltage
        (0x304 => regout0: ReadWrite<u32, RegOut::Register>),
        (0x308 => @END),
    }
}

register_bitfields! [u32,
    /// Task register
    Pselreset [
        /// GPIO number Px.nn onto which Reset is exposed
        PIN OFFSET(0) NUMBITS(5) [],
        /// GPIO port number Pn.xx onto with Reset is exposed
        PORT OFFSET(5) NUMBITS(1) [],
        /// Connection
        CONNECTION OFFSET(31) NUMBITS(1) [
            DISCONNECTED = 1,
            CONNECTED = 0
        ]
    ],
    /// Access port protection
    ApProtect [
        /// Ready event
        PALL OFFSET(0) NUMBITS(8) [
            /// Enable
            ENABLED = 0x00,
            /// Disable
            DISABLED = 0xff
        ]
    ],
    /// Processor debug control
    DebugControl [
        CPUNIDEN OFFSET(0) NUMBITS(8) [
            /// Enable
            ENABLED = 0xff,
            /// Disable
            DISABLED = 0x00
        ],
        CPUFPBEN OFFSET(8) NUMBITS(8) [
            /// Enable
            ENABLED = 0xff,
            /// Disable
            DISABLED = 0x00
        ]
    ],
    /// Setting of pins dedicated to NFC functionality: NFC antenna or GPIO
    NfcPins [
        /// Setting pins dedicated to NFC functionality
        PROTECT OFFSET(0) NUMBITS(1) [
            /// Operation as GPIO pins. Same protection as normal GPIO pins
            DISABLED = 0,
            /// Operation as NFC antenna pins. Configures the protection for
            /// NFC operation
            NFC = 1
        ]
    ],
    /// Enable external circuitry to be supplied from VDD pin
    ExtSupply [
        /// Enable external circuitry to be supplied from VDD pin
        EXTSUPPLY OFFSET(0) NUMBITS(1) [
            /// No current can be drawn from the VDD pin
            DISABLED = 0,
            /// It is allowed to supply external circuitry from the VDD pin
            ENABLED = 1
        ]
    ],
    /// GPIO reference voltage / external output supply voltage
    RegOut [
        /// Output voltage from REG0 regulator stage
        VOUT OFFSET(0) NUMBITS(3) [
            V1_8 = 0,
            V2_1 = 1,
            V2_4 = 2,
            V2_7 = 3,
            V3_0 = 4,
            V3_3 = 5,
            DEFAULT = 7
        ]
    ]
];

pub struct Uicr {
    registers: StaticRef<UicrRegisters>,
}

#[derive(Copy, Clone, PartialEq)]
/// Output voltage from REG0 regulator stage.
/// The value is board dependent (e.g. the nRF52840dk board uses 1.8V
/// whereas the nRF52840-Dongle requires 3.0V to light its LEDs).
/// When a chip is out of the factory or fully erased, the default value (7)
/// will output 1.8V.
pub enum Regulator0Output {
    V1_8 = 0,
    V2_1 = 1,
    V2_4 = 2,
    V2_7 = 3,
    V3_0 = 4,
    V3_3 = 5,
    DEFAULT = 7,
}

impl From<u32> for Regulator0Output {
    fn from(val: u32) -> Self {
        match val & 7 {
            0 => Regulator0Output::V1_8,
            1 => Regulator0Output::V2_1,
            2 => Regulator0Output::V2_4,
            3 => Regulator0Output::V2_7,
            4 => Regulator0Output::V3_0,
            5 => Regulator0Output::V3_3,
            7 => Regulator0Output::DEFAULT,
            _ => Regulator0Output::DEFAULT, // Invalid value, fall back to DEFAULT
        }
    }
}

impl Uicr {
    pub const fn new() -> Uicr {
        Uicr {
            registers: UICR_BASE,
        }
    }

    pub fn set_psel0_reset_pin(&self, pin: Pin) {
        self.registers.pselreset0.set(pin as u32);
    }

    pub fn get_psel0_reset_pin(&self) -> Option<Pin> {
        Pin::from_u32(self.registers.pselreset0.get())
    }

    pub fn set_psel1_reset_pin(&self, pin: Pin) {
        self.registers.pselreset1.set(pin as u32);
    }

    pub fn get_psel1_reset_pin(&self) -> Option<Pin> {
        Pin::from_u32(self.registers.pselreset1.get())
    }

    pub fn set_vout(&self, vout: Regulator0Output) {
        self.registers.regout0.modify(RegOut::VOUT.val(vout as u32));
    }

    pub fn get_vout(&self) -> Regulator0Output {
        Regulator0Output::from(self.registers.regout0.read(RegOut::VOUT))
    }

    pub fn set_nfc_pins_protection(&self, protected: bool) {
        if protected {
            self.registers.nfcpins.write(NfcPins::PROTECT::NFC);
        } else {
            self.registers.nfcpins.write(NfcPins::PROTECT::DISABLED);
        }
    }

    pub fn is_nfc_pins_protection_enabled(&self) -> bool {
        self.registers.nfcpins.matches_all(NfcPins::PROTECT::NFC)
    }

    pub fn get_dfu_params(&self) -> (u32, u32) {
        (
            self.registers.nrffw[0].get(), // DFU start address
            self.registers.nrffw[1].get(), // DFU settings address
        )
    }

    pub fn set_dfu_params(&self, dfu_start_addr: u32, dfu_settings_addr: u32) {
        self.registers.nrffw[0].set(dfu_start_addr);
        self.registers.nrffw[1].set(dfu_settings_addr);
    }

    pub fn is_ap_protect_enabled(&self) -> bool {
        // Here we compare to DISABLED value because any other value should enable the protection.
        !self
            .registers
            .approtect
            .matches_all(ApProtect::PALL::DISABLED)
    }

    pub fn set_ap_protect(&self) {
        self.registers.approtect.write(ApProtect::PALL::ENABLED);
    }
}

impl hil::firmware_protection::FirmwareProtection for Uicr {
    fn get_protection(&self) -> ProtectionLevel {
        let ap_protect_state = self.is_ap_protect_enabled();
        let cpu_debug_state = self
            .registers
            .debugctrl
            .matches_all(DebugControl::CPUNIDEN::ENABLED + DebugControl::CPUFPBEN::ENABLED);
        match (ap_protect_state, cpu_debug_state) {
            (false, _) => ProtectionLevel::NoProtection,
            (true, true) => ProtectionLevel::JtagDisabled,
            (true, false) => ProtectionLevel::FullyLocked,
        }
    }

    fn set_protection(&self, level: ProtectionLevel) -> ReturnCode {
        let current_level = self.get_protection();
        if current_level > level || level == ProtectionLevel::Unknown {
            return ReturnCode::EINVAL;
        }
        if current_level == level {
            return ReturnCode::EALREADY;
        }

        nvmc::Nvmc::new().configure_writeable();
        if level >= ProtectionLevel::JtagDisabled {
            self.set_ap_protect();
        }

        if level >= ProtectionLevel::FullyLocked {
            // Prevent CPU debug and flash patching. Leaving these enabled could
            // allow to circumvent protection.
            self.registers
                .debugctrl
                .write(DebugControl::CPUNIDEN::DISABLED + DebugControl::CPUFPBEN::DISABLED);
            // TODO(jmichel): prevent returning into bootloader if present
        }
        nvmc::Nvmc::new().configure_readonly();

        if self.get_protection() == level {
            ReturnCode::SUCCESS
        } else {
            ReturnCode::FAIL
        }
    }
}
