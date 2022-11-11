//! A USB HID client of the USB hardware interface

use super::descriptors;
use super::descriptors::Buffer64;
use super::descriptors::DescriptorType;
use super::descriptors::EndpointAddress;
use super::descriptors::EndpointDescriptor;
use super::descriptors::HIDCountryCode;
use super::descriptors::HIDDescriptor;
use super::descriptors::HIDSubordinateDescriptor;
use super::descriptors::InterfaceDescriptor;
use super::descriptors::ReportDescriptor;
use super::descriptors::TransferDirection;
use super::app::App;
use super::usb_ctap::CtapUsbClient;
use super::usbc_client_ctrl::ClientCtrl;
use core::cell::Cell;
use kernel::common::cells::OptionalCell;
use kernel::debug;
use kernel::hil;
use kernel::ReturnCode;
use kernel::hil::usb::TransferType;

static LANGUAGES: &'static [u16; 1] = &[
    0x0409, // English (United States)
];

#[cfg(not(feature = "vendor_hid"))]
const NUM_ENDPOINTS: usize = 1;
#[cfg(feature = "vendor_hid")]
const NUM_ENDPOINTS: usize = 2;

const ENDPOINT_NUM: usize = 1;
#[cfg(feature = "vendor_hid")]
const VENDOR_ENDPOINT_NUM: usize = ENDPOINT_NUM + 1;

static ENDPOINTS: &'static [usize] = &[
  ENDPOINT_NUM,
  #[cfg(feature = "vendor_hid")]
  VENDOR_ENDPOINT_NUM
];

static CTAP_REPORT_DESCRIPTOR: &'static [u8] = &[
    0x06, 0xD0, 0xF1, // HID_UsagePage ( FIDO_USAGE_PAGE ),
    0x09, 0x01, // HID_Usage ( FIDO_USAGE_CTAPHID ),
    0xA1, 0x01, // HID_Collection ( HID_Application ),
    0x09, 0x20, // HID_Usage ( FIDO_USAGE_DATA_IN ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, 0x40, // HID_ReportCount ( HID_INPUT_REPORT_BYTES ),
    0x81, 0x02, // HID_Input ( HID_Data | HID_Absolute | HID_Variable ),
    0x09, 0x21, // HID_Usage ( FIDO_USAGE_DATA_OUT ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, 0x40, // HID_ReportCount ( HID_OUTPUT_REPORT_BYTES ),
    0x91, 0x02, // HID_Output ( HID_Data | HID_Absolute | HID_Variable ),
    0xC0, // HID_EndCollection
];

#[cfg(feature = "vendor_hid")]
static VENDOR_REPORT_DESCRIPTOR: &'static [u8] = &[
    0x06, 0x00, 0xFF, // HID_UsagePage ( VENDOR ),
    0x09, 0x01, // HID_Usage ( Unused ),
    0xA1, 0x01, // HID_Collection ( HID_Application ),
    0x09, 0x20, // HID_Usage ( FIDO_USAGE_DATA_IN ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, 0x40, // HID_ReportCount ( HID_INPUT_REPORT_BYTES ),
    0x81, 0x02, // HID_Input ( HID_Data | HID_Absolute | HID_Variable ),
    0x09, 0x21, // HID_Usage ( FIDO_USAGE_DATA_OUT ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, 0x40, // HID_ReportCount ( HID_OUTPUT_REPORT_BYTES ),
    0x91, 0x02, // HID_Output ( HID_Data | HID_Absolute | HID_Variable ),
    0xC0, // HID_EndCollection
];

static CTAP_REPORT: ReportDescriptor<'static> = ReportDescriptor {
    desc: CTAP_REPORT_DESCRIPTOR,
};

#[cfg(feature = "vendor_hid")]
static VENDOR_REPORT: ReportDescriptor<'static> = ReportDescriptor {
  desc: VENDOR_REPORT_DESCRIPTOR,
};

static HID_SUB_DESCRIPTORS: &'static [HIDSubordinateDescriptor] = &[HIDSubordinateDescriptor {
    typ: DescriptorType::Report,
    len: CTAP_REPORT_DESCRIPTOR.len() as u16,
}];

#[cfg(feature = "vendor_hid")]
static VENDOR_HID_SUB_DESCRIPTORS: &'static [HIDSubordinateDescriptor] = &[HIDSubordinateDescriptor {
  typ: DescriptorType::Report,
  len: VENDOR_REPORT_DESCRIPTOR.len() as u16,
}];

static HID: HIDDescriptor<'static> = HIDDescriptor {
    hid_class: 0x0110,
    country_code: HIDCountryCode::NotSupported,
    sub_descriptors: HID_SUB_DESCRIPTORS,
};

#[cfg(feature = "vendor_hid")]
static VENDOR_HID: HIDDescriptor<'static> = HIDDescriptor {
  hid_class: 0x0110,
  country_code: HIDCountryCode::NotSupported,
  sub_descriptors: VENDOR_HID_SUB_DESCRIPTORS,
};

// The state of each endpoint.
struct EndpointState {
    endpoint: usize,
    in_buffer: Buffer64,
    out_buffer: Buffer64,

    tx_packet: OptionalCell<[u8; 64]>,
    pending_in: Cell<bool>,
    // Is there a delayed packet?
    delayed_out: Cell<bool>,
}

impl EndpointState {
    pub fn new(endpoint:usize) -> Self {
        EndpointState{
            endpoint: endpoint,
            in_buffer: Buffer64::default(),
            out_buffer: Buffer64::default(),
            tx_packet: OptionalCell::empty(),
            pending_in: Cell::new(false),
            delayed_out: Cell::new(false),
        }
    }
}

pub struct ClientCtapHID<'a, 'b, C: 'a> {
    client_ctrl: ClientCtrl<'a, 'static, C>,

    // Is there a pending OUT transaction happening?
    pending_out: Cell<bool>,
    next_endpoint_index: Cell<usize>,

    endpoints: [EndpointState; NUM_ENDPOINTS],

    // Interaction with the client
    client: OptionalCell<&'b dyn CtapUsbClient>,
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> ClientCtapHID<'a, 'b, C> {
    pub fn new(
        controller: &'a C,
        max_ctrl_packet_size: u8,
        vendor_id: u16,
        product_id: u16,
        strings: &'static [&'static str],
    ) -> Self {
        #[cfg(feature = "vendor_hid")]
        debug!("vendor_hid enabled.");

        let interfaces: &mut [InterfaceDescriptor] = &mut [
            // Interface declared in the FIDO2 specification, section 8.1.8.1
            InterfaceDescriptor {
                interface_class: 0x03, // HID
                interface_subclass: 0x00,
                interface_protocol: 0x00,
                ..InterfaceDescriptor::default()
            },
            // Vendor HID interface.
            #[cfg(feature = "vendor_hid")]
            InterfaceDescriptor {
                interface_number: 1,
                interface_class: 0x03, // HID
                interface_subclass: 0x00,
                interface_protocol: 0x00,
                ..InterfaceDescriptor::default()
            },
        ];

        let endpoints: &[&[EndpointDescriptor]] = &[&[
            // 2 Endpoints for FIDO
            EndpointDescriptor {
                endpoint_address: EndpointAddress::new_const(
                    ENDPOINT_NUM,
                    TransferDirection::HostToDevice,
                ),
                transfer_type: TransferType::Interrupt,
                max_packet_size: 64,
                interval: 5,
            },
            EndpointDescriptor {
                endpoint_address: EndpointAddress::new_const(
                    ENDPOINT_NUM,
                    TransferDirection::DeviceToHost,
                ),
                transfer_type: TransferType::Interrupt,
                max_packet_size: 64,
                interval: 5,
            },],
            // 2 Endpoints for FIDO
            #[cfg(feature = "vendor_hid")]
            &[
                EndpointDescriptor {
                    endpoint_address: EndpointAddress::new_const(
                        VENDOR_ENDPOINT_NUM,
                        TransferDirection::HostToDevice,
                    ),
                    transfer_type: TransferType::Interrupt,
                    max_packet_size: 64,
                    interval: 5,
                },
                EndpointDescriptor {
                    endpoint_address: EndpointAddress::new_const(
                        VENDOR_ENDPOINT_NUM,
                        TransferDirection::DeviceToHost,
                    ),
                    transfer_type: TransferType::Interrupt,
                    max_packet_size: 64,
                    interval: 5,
                },
            ],
        ];

        let (device_descriptor_buffer, other_descriptor_buffer) =
            descriptors::create_descriptor_buffers(
                descriptors::DeviceDescriptor {
                    vendor_id,
                    product_id,
                    manufacturer_string: 1,
                    product_string: 2,
                    serial_number_string: 3,
                    max_packet_size_ep0: max_ctrl_packet_size,
                    ..descriptors::DeviceDescriptor::default()
                },
                descriptors::ConfigurationDescriptor {
                    configuration_value: 1,
                    ..descriptors::ConfigurationDescriptor::default()
                },
                interfaces,
                endpoints,
                Some(&[
                    &HID,
                    #[cfg(feature = "vendor_hid")]
                    &VENDOR_HID,
                ]),
                None, // No CDC descriptor array
            );
        ClientCtapHID {
            client_ctrl: ClientCtrl::new(
                controller,
                device_descriptor_buffer,
                other_descriptor_buffer,
                Some([
                    &HID,
                    #[cfg(feature = "vendor_hid")]
                    &VENDOR_HID,
                ]),
                Some([
                    &CTAP_REPORT,
                    #[cfg(feature = "vendor_hid")]
                    &VENDOR_REPORT,
                ]),
                LANGUAGES,
                strings,
            ),
            pending_out: Cell::new(false),
            next_endpoint_index: Cell::new(0),
            endpoints: [
                EndpointState::new(ENDPOINT_NUM),
                #[cfg(feature = "vendor_hid")]
                EndpointState::new(VENDOR_ENDPOINT_NUM),
            ],
            client: OptionalCell::empty(),
        }
    }

    fn get_endpoint(&'a self, endpoint: usize) -> Option<&'a EndpointState> {
      for (i, ep) in ENDPOINTS.iter().enumerate() {
        if endpoint == *ep {
          return Some(&self.endpoints[i]);
        }
      }
      None
    }

    pub fn set_client(&'a self, client: &'b dyn CtapUsbClient) {
        self.client.set(client);
    }

    pub fn transmit_packet(&'a self, packet: &[u8], endpoint: usize) -> ReturnCode {
        if let Some(s) = self.get_endpoint(endpoint) {
            if s.pending_in.get() {
                // The previous packet has not yet been transmitted, reject the new one.
                return ReturnCode::EBUSY;
            }
            s.pending_in.set(true);
            let mut buf: [u8; 64] = [0; 64];
            buf.copy_from_slice(packet);
            s.tx_packet.set(buf);
            // Alert the controller that we now have data to send on the Interrupt IN endpoint.
            self.controller().endpoint_resume_in(endpoint);
            ReturnCode::SUCCESS
        } else {
            // Unsupported endpoint
            ReturnCode::EINVAL
        }
    }

    pub fn receive_packet(&'a self, app: &mut App) {
        if self.pending_out.get() {
            // The previous packet has not yet been received, reject the new one.
        } else {
            self.pending_out.set(true);
            // Process the next endpoint that has a delayed packet.
            for i in self.next_endpoint_index.get()..self.next_endpoint_index.get() + NUM_ENDPOINTS {
                let s = &self.endpoints[i % NUM_ENDPOINTS];
                // In case we reported Delay before, send the pending packet back to the client.
                // Otherwise, there's nothing to do, the controller will send us a packet_out when a
                // packet arrives.
                if s.delayed_out.take() {
                    if self.send_packet_to_client(s.endpoint, Some(app)) {
                        // If that succeeds, alert the controller that we can now
                        // receive data on the Interrupt OUT endpoint.
                        self.controller().endpoint_resume_out(s.endpoint);
                    }
                }
            }
        }
    }

    // Send an OUT packet available in the controller back to the client.
    // This returns false if the client is not ready to receive a packet, and true if the client
    // successfully accepted the packet.
    fn send_packet_to_client(&'a self, endpoint: usize, app: Option<&mut App>) -> bool {
        if let Some(s) = self.get_endpoint(endpoint) {
            // Copy the packet into a buffer to send to the client.
            let mut buf: [u8; 64] = [0; 64];
              for (i, x) in s.out_buffer.buf.iter().enumerate() {
                buf[i] = x.get();
            }

            assert!(!s.delayed_out.get());

            // Notify the client
            if self
                .client
                .map_or(false, |client| client.can_receive_packet(&app))
            {
                assert!(self.pending_out.take());

                // Clear any pending packet on the transmitting side.
                // It's up to the client to handle the received packet and decide if this packet
                // should be re-transmitted or not.
                self.cancel_in_transaction(endpoint);

                self.client.map(|client| client.packet_received(&buf, endpoint, app));
                // Update next packet to send.
                for (i, ep) in self.endpoints.iter().enumerate() {
                    if ep.endpoint == endpoint {
                        self.next_endpoint_index.set((i + 1) % NUM_ENDPOINTS);
                        break;
                    }
                }
                true
            } else {
                // Cannot receive now, indicate a delay to the controller.
                s.delayed_out.set(true);
                false
            }
        } else {
            // Unsupported endpoint
            false
        }
    }

    // Cancel transaction(s) in process. |endpoint| of 0 indicates all endpoints.
    pub fn cancel_transaction(&'a self, endpoint: usize) -> bool {
        if endpoint > 0 {
          return self.cancel_in_transaction(endpoint) | self.cancel_out_transaction(endpoint);
        }
        let mut r = false;
        for (_, s) in self.endpoints.iter().enumerate() {
            r |= self.cancel_in_transaction(s.endpoint) | self.cancel_out_transaction(s.endpoint);
        }
        r
    }

    fn cancel_in_transaction(&'a self, endpoint: usize) -> bool {
        if let Some(s) = self.get_endpoint(endpoint) {
            s.tx_packet.take();
            s.pending_in.take()
        } else {
            // Unsupported endpoint
          false
        }
    }

    fn cancel_out_transaction(&'a self, endpoint: usize) -> bool {
        if let Some(_) = self.get_endpoint(endpoint) {
            self.pending_out.take()
        } else {
            // Unsupported endpoint
          false
        }
    }

    #[inline]
    fn controller(&'a self) -> &'a C {
        self.client_ctrl.controller()
    }
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> hil::usb::Client<'a> for ClientCtapHID<'a, 'b, C> {
    fn enable(&'a self) {
        // Set up the default control endpoint
        self.client_ctrl.enable();

        // Set up the interrupt in-out endpoint(s).
        for (i, endpoint) in ENDPOINTS.iter().enumerate() {
            self.controller()
                .endpoint_set_in_buffer(*endpoint, &self.endpoints[i].in_buffer.buf);
            self.controller()
                .endpoint_set_out_buffer(*endpoint, &self.endpoints[i].out_buffer.buf);
            self.controller()
                .endpoint_in_out_enable(TransferType::Interrupt, *endpoint);
          }
    }

    fn attach(&'a self) {
        self.client_ctrl.attach();
    }

    fn bus_reset(&'a self) {
        // Should the client initiate reconfiguration here?
        // For now, the hardware layer does it.

        debug!("Bus reset");
    }

    /// Handle a Control Setup transaction
    fn ctrl_setup(&'a self, endpoint: usize) -> hil::usb::CtrlSetupResult {
        self.client_ctrl.ctrl_setup(endpoint)
    }

    /// Handle a Control In transaction
    fn ctrl_in(&'a self, endpoint: usize) -> hil::usb::CtrlInResult {
        self.client_ctrl.ctrl_in(endpoint)
    }

    /// Handle a Control Out transaction
    fn ctrl_out(&'a self, endpoint: usize, packet_bytes: u32) -> hil::usb::CtrlOutResult {
        self.client_ctrl.ctrl_out(endpoint, packet_bytes)
    }

    fn ctrl_status(&'a self, endpoint: usize) {
        self.client_ctrl.ctrl_status(endpoint)
    }

    /// Handle the completion of a Control transfer
    fn ctrl_status_complete(&'a self, endpoint: usize) {
        self.client_ctrl.ctrl_status_complete(endpoint)
    }

    /// Handle a Bulk/Interrupt IN transaction
    fn packet_in(&'a self, transfer_type: TransferType, endpoint: usize) -> hil::usb::InResult {
        match transfer_type {
            TransferType::Bulk => hil::usb::InResult::Error,
            TransferType::Interrupt => {
                if let Some(s) = self.get_endpoint(endpoint) {
                    if let Some(packet) = s.tx_packet.take() {
                        let buf = &s.in_buffer.buf;
                        for i in 0..64 {
                            buf[i].set(packet[i]);
                        }
                        hil::usb::InResult::Packet(64)
                    } else {
                        // Nothing to send
                        hil::usb::InResult::Delay
                    }
                } else {
                    // Unsupported endpoint
                    return hil::usb::InResult::Error
                }
            }
            TransferType::Control | TransferType::Isochronous => unreachable!(),
        }
    }

    /// Handle a Bulk/Interrupt OUT transaction
    fn packet_out(
        &'a self,
        transfer_type: TransferType,
        endpoint: usize,
        packet_bytes: u32,
    ) -> hil::usb::OutResult {
        match transfer_type {
            TransferType::Bulk => hil::usb::OutResult::Error,
            TransferType::Interrupt => {
                if endpoint == 0 || endpoint > NUM_ENDPOINTS {
                    return hil::usb::OutResult::Error;
                }

                if packet_bytes != 64 {
                    // Cannot process this packet
                    hil::usb::OutResult::Error
                } else {
                    if self.send_packet_to_client(endpoint, None) {
                        hil::usb::OutResult::Ok
                    } else {
                        hil::usb::OutResult::Delay
                    }
                }
            }
            TransferType::Control | TransferType::Isochronous => unreachable!(),
        }
    }

    fn packet_transmitted(&'a self, endpoint: usize) {
        if let Some(s) = self.get_endpoint(endpoint) {
            if s.tx_packet.is_some() {
                panic!("Unexpected tx_packet while a packet was being transmitted.");
            }
            s.pending_in.set(false);

            // Clear any pending packet on the receiving side.
            // It's up to the client to handle the transmitted packet and decide if they want to
            // receive another packet.
            self.cancel_out_transaction(endpoint);

            // Notify the client
            self.client.map(|client| client.packet_transmitted());
        } else {
            panic!("Unexpected transmission on ep {}", endpoint);
        }
    }
  }
