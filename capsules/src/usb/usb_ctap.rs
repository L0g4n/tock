use super::app::{App, Side};
use super::usbc_ctap_hid::ClientCtapHID;
use kernel::errorcode::ErrorCode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil;
use kernel::hil::usb::Client;
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::ProcessId;

/// Syscall number
use crate::driver;
pub const DRIVER_NUM: usize = driver::NUM::UsbCtap as usize;

pub const CTAP_CMD_CHECK: usize = 0;
pub const CTAP_CMD_CONNECT: usize = 1;
pub const CTAP_CMD_TRANSMIT: usize = 2;
pub const CTAP_CMD_RECEIVE: usize = 3;
pub const CTAP_CMD_TRANSMIT_OR_RECEIVE: usize = 4;
pub const CTAP_CMD_CANCEL: usize = 5;

/// Ids for read-only allow buffers
mod ro_allow {
    pub const TRANSMIT: usize = 0;
    pub const TRANSMIT_OR_RECEIVE: usize = 1;
    pub const COUNT: u8 = 2;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const RECEIVE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for scheduling the upcalls
///
/// They **must** match the the subscribe numbers which were used by the process to
/// subscribe to the upcall.
mod upcalls {
    pub const TRANSMITTED: usize = 0;
    pub const RECEIVED: usize = 1;
    pub const COUNT: u8 = 2;
}

type CtabUsbDriverGrant = Grant<
    App,
    UpcallCount<{ upcalls::COUNT }>,
    AllowRoCount<{ ro_allow::COUNT }>,
    AllowRwCount<{ rw_allow::COUNT }>,
>;

pub trait CtapUsbClient {
    // Whether this client is ready to receive a packet. This must be checked before calling
    // packet_received(). If App is not supplied, it will be found from the implemntation's
    // members.
    fn can_receive_packet(&self, app: &Option<&mut App>) -> bool;

    // Signal to the client that a packet has been received.
    fn packet_received(&self, packet: &[u8; 64], endpoint: usize, app: Option<&mut App>);

    // Signal to the client that a packet has been transmitted.
    fn packet_transmitted(&self);
}

pub struct CtapUsbSyscallDriver<'a, 'b, C: 'a> {
    usb_client: &'a ClientCtapHID<'a, 'b, C>,
    apps: CtabUsbDriverGrant,
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> CtapUsbSyscallDriver<'a, 'b, C> {
    pub fn new(usb_client: &'a ClientCtapHID<'a, 'b, C>, apps: CtabUsbDriverGrant) -> Self {
        CtapUsbSyscallDriver { usb_client, apps }
    }

    fn app_packet_received(
        &self,
        packet: &[u8; 64],
        endpoint: usize,
        app: &mut App,
        kernel: &GrantKernelData,
    ) {
        if app.connected && app.waiting && app.side.map_or(false, |side| side.can_receive()) {
            let _ = kernel
                .get_readwrite_processbuffer(rw_allow::RECEIVE)
                .and_then(|recv| recv.mut_enter(|dest| dest.copy_from_slice(packet)));
            app.waiting = false;
            // reset the client state
            app.check_side();
            // Signal to the app that a packet is ready.
            // TODO: passing the upcallid again in the registers is not needed anymore with Tock 2.0,
            // but is currently still there for backwards compatibility
            kernel
                .schedule_upcall(upcalls::RECEIVED, (upcalls::RECEIVED, endpoint, 0))
                .ok();
        }
    }
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> CtapUsbClient for CtapUsbSyscallDriver<'a, 'b, C> {
    fn can_receive_packet(&self, app: &Option<&mut App>) -> bool {
        let mut result = false;
        match app {
            None => {
                for app in self.apps.iter() {
                    app.enter(|a, _| {
                        if a.connected {
                            result = a.can_receive_packet();
                        }
                    })
                }
            }
            Some(a) => result = a.can_receive_packet(),
        }
        result
    }

    // TODO: interface weird. we need the reentry to get the kernel data
    fn packet_received(&self, packet: &[u8; 64], endpoint: usize, _app: Option<&mut App>) {
        for app in self.apps.iter() {
            app.enter(|a, kernel_data| {
                self.app_packet_received(packet, endpoint, a, kernel_data);
            })
        }
    }

    fn packet_transmitted(&self) {
        for app in self.apps.iter() {
            app.enter(|app, kernel_data| {
                if app.connected
                    && app.waiting
                    && app.side.map_or(false, |side| side.can_transmit())
                {
                    app.waiting = false;
                    // reset the client state
                    app.check_side();
                    // Signal to the app that the packet was sent.
                    kernel_data
                        .schedule_upcall(upcalls::TRANSMITTED, (upcalls::TRANSMITTED, 0, 0))
                        .unwrap();
                }
            });
        }
    }
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> SyscallDriver for CtapUsbSyscallDriver<'a, 'b, C> {
    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }

    fn command(
        &self,
        cmd_num: usize,
        endpoint: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match cmd_num {
            CTAP_CMD_CHECK => CommandReturn::success(),
            CTAP_CMD_CONNECT => {
                // First, check if any app is already connected to this driver.
                let mut busy = false;
                for app in self.apps.iter() {
                    app.enter(|app, _| {
                        busy |= app.connected;
                    });
                }

                self.apps
                    .enter(process_id, |app, _| {
                        if app.connected {
                            CommandReturn::failure(ErrorCode::ALREADY)
                        } else if busy {
                            CommandReturn::failure(ErrorCode::BUSY)
                        } else {
                            self.usb_client.enable();
                            self.usb_client.attach();
                            app.connected = true;
                            CommandReturn::success()
                        }
                    })
                    .unwrap_or_else(|err| err.into())
            }
            CTAP_CMD_TRANSMIT => self
                .apps
                .enter(process_id, |app, kernel| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        // set the client state to transmit packets
                        if !app.set_side(Side::Transmit) {
                            return CommandReturn::failure(ErrorCode::INVAL);
                        }

                        if app.is_ready_for_command(Side::Transmit) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else {
                                kernel
                                    .get_readonly_processbuffer(ro_allow::TRANSMIT)
                                    .and_then(|buffer| {
                                        buffer.enter(|buf| {
                                            let mut packet: [u8; 64] = [0; 64];
                                            buf.copy_to_slice(&mut packet);
                                            let r =
                                                self.usb_client.transmit_packet(&packet, endpoint);

                                            if r.is_success() {
                                                app.waiting = true;
                                            }

                                            r
                                        })
                                    })
                                    .unwrap_or(CommandReturn::failure(ErrorCode::FAIL))
                            }
                        } else {
                            CommandReturn::failure(ErrorCode::INVAL)
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_RECEIVE => self
                .apps
                .enter(process_id, |app, _| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        // set the client state to recive packets
                        if !app.set_side(Side::Receive) {
                            return CommandReturn::failure(ErrorCode::INVAL);
                        }
                        if app.is_ready_for_command(Side::Receive) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else {
                                app.waiting = true;
                                self.usb_client.receive_packet(app);
                                CommandReturn::success()
                            }
                        } else {
                            CommandReturn::failure(ErrorCode::INVAL)
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_TRANSMIT_OR_RECEIVE => self
                .apps
                .enter(process_id, |app, kernel| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        // set the client state
                        if !app.set_side(Side::TransmitOrReceive) {
                            return CommandReturn::failure(ErrorCode::INVAL);
                        }

                        if app.is_ready_for_command(Side::TransmitOrReceive) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else {
                                // send a packet before receiving one
                                let r = kernel
                                    .get_readonly_processbuffer(ro_allow::TRANSMIT_OR_RECEIVE)
                                    .and_then(|process_buffer| {
                                        process_buffer.enter(|buf| {
                                            let mut packet: [u8; 64] = [0; 64];
                                            buf.copy_to_slice(&mut packet);

                                            // Indicates to the driver that we have a packet to send.
                                            self.usb_client.transmit_packet(&packet, endpoint)
                                        })
                                    })
                                    .unwrap_or(CommandReturn::failure(ErrorCode::FAIL));
                                if !r.is_success() {
                                    return r;
                                }

                                // Indicates to the driver that we can receive any pending packet.
                                app.waiting = true;
                                self.usb_client.receive_packet(app);

                                CommandReturn::success()
                            }
                        } else {
                            CommandReturn::failure(ErrorCode::INVAL)
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_CANCEL => self
                .apps
                .enter(process_id, |app, _| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        if app.waiting {
                            // FIXME: if cancellation failed, the app should still wait. But that
                            // doesn't work yet.
                            app.waiting = false;
                            if self.usb_client.cancel_transaction(endpoint) {
                                CommandReturn::success()
                            } else {
                                // Cannot cancel now because the transaction is already in process.
                                // The app should wait for the callback instead.
                                CommandReturn::failure(ErrorCode::BUSY)
                            }
                        } else {
                            CommandReturn::failure(ErrorCode::ALREADY)
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }
}
