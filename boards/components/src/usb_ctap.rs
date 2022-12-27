//! Component for CTAP over USB.

use capsules::usb::usb_ctap::CtapUsbSyscallDriver;
use capsules::usb::usbc_ctap_hid::ClientCtapHID;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;

// Setup static space for the objects.
#[macro_export]
macro_rules! usb_ctap_component_static {
    ($C:ty $(,)?) => {{
        use capsules::usb::usb_ctap::CtapUsbSyscallDriver;
        use capsules::usb::usbc_ctap_hid::ClientCtapHID;
        // use core::mem::MaybeUninit;
        // static mut BUF1: MaybeUninit<ClientCtapHID<'static, 'static, $C>> = MaybeUninit::uninit();
        // static mut BUF2: MaybeUninit<CtapUsbSyscallDriver<'static, 'static, $C>> =
        //     MaybeUninit::uninit();
        let hid = kernel::static_buf!(ClientCtapHID<'static, 'static, $C>);
        let driver = kernel::static_buf!(CtapUsbSyscallDriver<'static, 'static, $C>);


        (hid, driver)
    };};
}

pub struct UsbCtapComponent<C: 'static + hil::usb::UsbController<'static>> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    controller: &'static C,
    max_ctrl_packet_size: u8,
    vendor_id: u16,
    product_id: u16,
    strings: &'static [&'static str],
}

impl<C: 'static + hil::usb::UsbController<'static>> UsbCtapComponent<C> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        controller: &'static C,
        max_ctrl_packet_size: u8,
        vendor_id: u16,
        product_id: u16,
        strings: &'static [&'static str],
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            controller,
            max_ctrl_packet_size,
            vendor_id,
            product_id,
            strings,
        }
    }
}

impl<C: 'static + hil::usb::UsbController<'static>> Component for UsbCtapComponent<C> {
    type StaticInput = (
        &'static mut MaybeUninit<ClientCtapHID<'static, 'static, C>>,
        &'static mut MaybeUninit<CtapUsbSyscallDriver<'static, 'static, C>>,
    );
    type Output = &'static CtapUsbSyscallDriver<'static, 'static, C>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let usb_ctap = s.0.write(ClientCtapHID::new(
            self.controller,
            self.max_ctrl_packet_size,
            self.vendor_id,
            self.product_id,
            self.strings,
        ));
        self.controller.set_client(usb_ctap);

        // Configure the USB userspace driver
        let usb_driver = s.1.write(CtapUsbSyscallDriver::new(
            usb_ctap,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));
        usb_ctap.set_client(usb_driver);

        usb_driver
    }
}
