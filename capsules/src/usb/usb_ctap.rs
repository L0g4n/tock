use core::mem;

use super::usbc_ctap_hid::ClientCtapHID;
use kernel::errorcode::ErrorCode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil;
use kernel::hil::usb::Client;
use kernel::processbuffer::WriteableProcessBuffer;
use kernel::processbuffer::{ReadWriteProcessBuffer, ReadableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::upcall::UpcallId;
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

pub const CTAP_ALLOW_TRANSMIT: usize = 1;
pub const CTAP_ALLOW_RECEIVE: usize = 2;
pub const CTAP_ALLOW_TRANSMIT_OR_RECEIVE: usize = 3;

pub const CTAP_SUBSCRIBE_TRANSMIT: usize = 1;
pub const CTAP_SUBSCRIBE_RECEIVE: usize = 2;
pub const CTAP_SUBSCRIBE_TRANSMIT_OR_RECEIVE: usize = 3;

pub const CTAP_CALLBACK_TRANSMITED: usize = 1;
pub const CTAP_CALLBACK_RECEIVED: usize = 2;

type CtabUsbDriverGrant = Grant<App, UpcallCount<1>, AllowRoCount<1>, AllowRwCount<1>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Transmit,
    Receive,
    TransmitOrReceive,
}

impl Side {
    fn can_transmit(&self) -> bool {
        match self {
            Side::Transmit | Side::TransmitOrReceive => true,
            Side::Receive => false,
        }
    }

    fn can_receive(&self) -> bool {
        match self {
            Side::Receive | Side::TransmitOrReceive => true,
            Side::Transmit => false,
        }
    }
}

#[derive(Default)]
pub struct App {
    // Only one app can be connected to this driver, to avoid needing to route packets among apps.
    // This field tracks this status.
    connected: bool,
    // Currently enabled transaction side. Subscribing to a callback or allowing a buffer
    // automatically sets the corresponding side. Clearing both the callback and the buffer resets
    // the side to None.
    side: Option<Side>,
    upcall: Option<UpcallId>,
    buffer: Option<ReadWriteProcessBuffer>,
    // Whether the app is waiting for the kernel signaling a packet transfer.
    waiting: bool,
}

impl App {
    fn check_side(&mut self) {
        if self.upcall.is_none() && self.buffer.is_none() && !self.waiting {
            self.side = None;
        }
    }

    fn set_side(&mut self, side: Side) -> bool {
        match self.side {
            None => {
                self.side = Some(side);
                true
            }
            Some(app_side) => side == app_side,
        }
    }

    fn is_ready_for_command(&self, side: Side) -> bool {
        self.buffer.is_some() && self.upcall.is_some() && self.side == Some(side)
    }
}

pub trait CtapUsbClient {
    // Whether this client is ready to receive a packet. This must be checked before calling
    // packet_received().
    fn can_receive_packet(&self) -> bool;

    // Signal to the client that a packet has been received.
    fn packet_received(&self, packet: &[u8; 64]);

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
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> CtapUsbClient for CtapUsbSyscallDriver<'a, 'b, C> {
    fn can_receive_packet(&self) -> bool {
        let mut result = false;
        for app in self.apps.iter() {
            app.enter(|app, _| {
                if app.connected {
                    result = app.waiting
                        && app.side.map_or(false, |side| side.can_receive())
                        && app.buffer.is_some();
                }
            });
        }
        result
    }

    fn packet_received(&self, packet: &[u8; 64]) {
        for app in self.apps.iter() {
            app.enter(|app, kernel_data| {
                if app.connected && app.waiting && app.side.map_or(false, |side| side.can_receive())
                {
                    if let Some(buf) = &mut app.buffer {
                        // Copy the packet to the app's allowed buffer.
                        buf.mut_enter(|mut_buf| mut_buf.copy_from_slice(packet))
                            .unwrap();
                        app.waiting = false;
                        // Signal to the app that a packet is ready.
                        kernel_data
                            .schedule_upcall(0, (CTAP_CALLBACK_RECEIVED, 0, 0))
                            .unwrap();
                    }
                }
            });
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
                        .schedule_upcall(0, (CTAP_CALLBACK_TRANSMITED, 0, 0))
                        .unwrap();
                }
            });
        }
    }
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> SyscallDriver for CtapUsbSyscallDriver<'a, 'b, C> {
    fn allow_userspace_readable(
        &self,
        app_process_id: ProcessId,
        which: usize,
        mut slice: kernel::processbuffer::UserspaceReadableProcessBuffer,
    ) -> Result<
        kernel::processbuffer::UserspaceReadableProcessBuffer,
        (
            kernel::processbuffer::UserspaceReadableProcessBuffer,
            ErrorCode,
        ),
    > {
        let side = match which {
            CTAP_ALLOW_TRANSMIT => Side::Transmit,
            CTAP_ALLOW_RECEIVE => Side::Receive,
            CTAP_ALLOW_TRANSMIT_OR_RECEIVE => Side::TransmitOrReceive,
            _ => return Err((slice, ErrorCode::NOSUPPORT)),
        };

        let res = self
            .apps
            .enter(app_process_id, |app, _| {
                if !app.connected {
                    Err(ErrorCode::RESERVE)
                } else {
                    if slice.len() != 64 {
                        return Err(ErrorCode::INVAL);
                    }
                    if !app.set_side(side) {
                        return Err(ErrorCode::ALREADY);
                    }
                    app.check_side();

                    if let Some(buf) = &mut app.buffer {
                        mem::swap(buf, &mut slice);
                        Ok(())
                    } else {
                        Err(ErrorCode::FAIL)
                    }
                }
            })
            .map_err(ErrorCode::from);

        if let Err(e) = res {
            Err((slice, e))
        } else {
            Ok(slice)
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }

    /*
    fn subscribe(
        &self,
        subscribe_num: usize,
        callback: Option<Callback>,
        processId: ProcessId,
    ) -> Result<(), ErrorCode> {
        let side = match subscribe_num {
            CTAP_SUBSCRIBE_TRANSMIT => Side::Transmit,
            CTAP_SUBSCRIBE_RECEIVE => Side::Receive,
            CTAP_SUBSCRIBE_TRANSMIT_OR_RECEIVE => Side::TransmitOrReceive,
            _ => return Err(ErrorCode::NOSUPPORT),
        };
        self.apps
            .enter(processId, |app, _| {
                if !app.connected {
                    Err(ErrorCode::RESERVE)
                } else {
                    if !app.set_side(side) {
                        return Err(ErrorCode::ALREADY);
                    }
                    app.upcall = callback;
                    app.check_side();
                    Ok(())
                }
            })
            .unwrap_or_else(|err| err.into())
    } */

    fn command(
        &self,
        cmd_num: usize,
        _arg1: usize,
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
                .enter(process_id, |app, _| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        if app.is_ready_for_command(Side::Transmit) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else if self.usb_client.transmit_packet(
                                app.buffer
                                    .as_ref()
                                    .unwrap()
                                    .enter(|slice| {
                                        let mut packet: [u8; 64] = [0; 64];
                                        slice.copy_to_slice(&mut packet);
                                        packet
                                    })
                                    .unwrap()
                                    .as_ref(),
                            ) {
                                app.waiting = true;
                                CommandReturn::success()
                            } else {
                                CommandReturn::failure(ErrorCode::BUSY)
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
                        if app.is_ready_for_command(Side::Receive) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else {
                                app.waiting = true;
                                self.usb_client.receive_packet();
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
                .enter(process_id, |app, _| {
                    if !app.connected {
                        CommandReturn::failure(ErrorCode::RESERVE)
                    } else {
                        if app.is_ready_for_command(Side::TransmitOrReceive) {
                            if app.waiting {
                                CommandReturn::failure(ErrorCode::ALREADY)
                            } else {
                                // Indicates to the driver that we can receive any pending packet.
                                app.waiting = true;
                                self.usb_client.receive_packet();

                                if !app.waiting {
                                    // The call to receive_packet() collected a pending packet.
                                    CommandReturn::success()
                                } else {
                                    // Indicates to the driver that we have a packet to send.
                                    if self.usb_client.transmit_packet(
                                        app.buffer
                                            .as_ref()
                                            .unwrap()
                                            .enter(|slice| {
                                                let mut packet: [u8; 64] = [0; 64];
                                                slice.copy_to_slice(&mut packet);
                                                packet
                                            })
                                            .unwrap()
                                            .as_ref(),
                                    ) {
                                        CommandReturn::success()
                                    } else {
                                        CommandReturn::failure(ErrorCode::BUSY)
                                    }
                                }
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
                            if self.usb_client.cancel_transaction() {
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
