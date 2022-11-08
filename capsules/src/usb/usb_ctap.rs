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

// todo: figure out what do with them
pub const CTAP_ALLOW_TRANSMIT: usize = 1;
pub const CTAP_ALLOW_RECEIVE: usize = 2;
pub const CTAP_ALLOW_TRANSMIT_OR_RECEIVE: usize = 3;

// todo: figure out what do with them
// ids for the subscribe syscalls
pub const CTAP_SUBSCRIBE_TRANSMIT: usize = 1;
pub const CTAP_SUBSCRIBE_RECEIVE: usize = 2;
pub const CTAP_SUBSCRIBE_TRANSMIT_OR_RECEIVE: usize = 3;

// the different kinds of subscribe upcalls triggered inside the application when the corresponding event happens
pub const CTAP_CALLBACK_TRANSMITED_SUBSCRIBE_NUM: usize = 0;
pub const CTAP_CALLBACK_RECEIVED_SUBSCRIBE_NUM: usize = 1;

type CtabUsbDriverGrant = Grant<App, UpcallCount<2>, AllowRoCount<1>, AllowRwCount<1>>;

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
        kernel_data: &GrantKernelData,
    ) {
        if app.connected && app.waiting && app.side.map_or(false, |side| side.can_receive()) {
            kernel_data
                .get_readwrite_processbuffer(1)
                .and_then(|process_buffer| {
                    process_buffer
                        .mut_enter(|buf| buf.copy_from_slice(packet))
                        .unwrap();
                    app.waiting = false;
                    // Signal to the app that a packet is ready.
                    kernel_data
                        .schedule_upcall(CTAP_CALLBACK_RECEIVED_SUBSCRIBE_NUM, (endpoint, 0, 0))
                        .unwrap();
                    // reset the client state
                    app.check_side();

                    Ok(())
                })
                .unwrap();
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
                    // Signal to the app that the packet was sent.
                    kernel_data
                        .schedule_upcall(CTAP_CALLBACK_TRANSMITED_SUBSCRIBE_NUM, (0, 0, 0))
                        .unwrap();

                    // reset the client state
                    app.check_side();
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
                                    .get_readonly_processbuffer(1)
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
                                    .get_readonly_processbuffer(1)
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
