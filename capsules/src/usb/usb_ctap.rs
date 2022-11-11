use super::app::{App, Side};
use super::usbc_ctap_hid::ClientCtapHID;
use kernel::hil::usb::Client;
use kernel::{hil, AppId, AppSlice, Callback, Driver, Grant, ReturnCode, Shared};

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
    apps: Grant<App>,
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> CtapUsbSyscallDriver<'a, 'b, C> {
    pub fn new(usb_client: &'a ClientCtapHID<'a, 'b, C>, apps: Grant<App>) -> Self {
        CtapUsbSyscallDriver { usb_client, apps }
    }

    fn app_packet_received(&self, packet: &[u8; 64], endpoint: usize, app: &mut App) {
        if app.connected && app.waiting && app.side.map_or(false, |side| side.can_receive()) {
            if let Some(buf) = &mut app.buffer {
                // Copy the packet to the app's allowed buffer.
                buf.as_mut().copy_from_slice(packet);
                app.waiting = false;
                // Signal to the app that a packet is ready.
                app.callback
                    .map(|mut cb| cb.schedule(CTAP_CALLBACK_RECEIVED, endpoint, 0));
            }
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

    fn packet_received(&self, packet: &[u8; 64], endpoint: usize, app: Option<&mut App>) {
        match app {
            None => {
                for app in self.apps.iter() {
                    app.enter(|a, _| {
                        self.app_packet_received(packet, endpoint, a);
                    })
                }
            }
            Some(a) => self.app_packet_received(packet, endpoint, a),
        }
    }

    fn packet_transmitted(&self) {
        for app in self.apps.iter() {
            app.enter(|app, _| {
                if app.connected
                    && app.waiting
                    && app.side.map_or(false, |side| side.can_transmit())
                {
                    app.waiting = false;
                    // Signal to the app that the packet was sent.
                    app.callback
                        .map(|mut cb| cb.schedule(CTAP_CALLBACK_TRANSMITED, 0, 0));
                }
            });
        }
    }
}

impl<'a, 'b, C: hil::usb::UsbController<'a>> Driver for CtapUsbSyscallDriver<'a, 'b, C> {
    fn allow(
        &self,
        appid: AppId,
        allow_num: usize,
        slice: Option<AppSlice<Shared, u8>>,
    ) -> ReturnCode {
        let side = match allow_num {
            CTAP_ALLOW_TRANSMIT => Side::Transmit,
            CTAP_ALLOW_RECEIVE => Side::Receive,
            CTAP_ALLOW_TRANSMIT_OR_RECEIVE => Side::TransmitOrReceive,
            _ => return ReturnCode::ENOSUPPORT,
        };
        self.apps
            .enter(appid, |app, _| {
                if !app.connected {
                    ReturnCode::ERESERVE
                } else {
                    if let Some(buf) = &slice {
                        if buf.len() != 64 {
                            return ReturnCode::EINVAL;
                        }
                    }
                    if !app.set_side(side) {
                        return ReturnCode::EALREADY;
                    }
                    app.buffer = slice;
                    app.check_side();
                    ReturnCode::SUCCESS
                }
            })
            .unwrap_or_else(|err| err.into())
    }

    fn subscribe(
        &self,
        subscribe_num: usize,
        callback: Option<Callback>,
        appid: AppId,
    ) -> ReturnCode {
        let side = match subscribe_num {
            CTAP_SUBSCRIBE_TRANSMIT => Side::Transmit,
            CTAP_SUBSCRIBE_RECEIVE => Side::Receive,
            CTAP_SUBSCRIBE_TRANSMIT_OR_RECEIVE => Side::TransmitOrReceive,
            _ => return ReturnCode::ENOSUPPORT,
        };
        self.apps
            .enter(appid, |app, _| {
                if !app.connected {
                    ReturnCode::ERESERVE
                } else {
                    if !app.set_side(side) {
                        return ReturnCode::EALREADY;
                    }
                    app.callback = callback;
                    app.check_side();
                    ReturnCode::SUCCESS
                }
            })
            .unwrap_or_else(|err| err.into())
    }

    fn command(&self, cmd_num: usize, endpoint: usize, _arg2: usize, appid: AppId) -> ReturnCode {
        match cmd_num {
            CTAP_CMD_CHECK => ReturnCode::SUCCESS,
            CTAP_CMD_CONNECT => {
                // First, check if any app is already connected to this driver.
                let mut busy = false;
                for app in self.apps.iter() {
                    app.enter(|app, _| {
                        busy |= app.connected;
                    });
                }

                self.apps
                    .enter(appid, |app, _| {
                        if app.connected {
                            ReturnCode::EALREADY
                        } else if busy {
                            ReturnCode::EBUSY
                        } else {
                            self.usb_client.enable();
                            self.usb_client.attach();
                            app.connected = true;
                            ReturnCode::SUCCESS
                        }
                    })
                    .unwrap_or_else(|err| err.into())
            }
            CTAP_CMD_TRANSMIT => self
                .apps
                .enter(appid, |app, _| {
                    if !app.connected {
                        ReturnCode::ERESERVE
                    } else {
                        if app.is_ready_for_command(Side::Transmit) {
                            if app.waiting {
                                ReturnCode::EALREADY
                            } else {
                                let r = self
                                    .usb_client
                                    .transmit_packet(app.buffer.as_ref().unwrap().as_ref(), endpoint);
                                if r == ReturnCode::SUCCESS {
                                    app.waiting = true;
                                }
                                r
                            }
                        } else {
                            ReturnCode::EINVAL
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_RECEIVE => self
                .apps
                .enter(appid, |app, _| {
                    if !app.connected {
                        ReturnCode::ERESERVE
                    } else {
                        if app.is_ready_for_command(Side::Receive) {
                            if app.waiting {
                                ReturnCode::EALREADY
                            } else {
                                app.waiting = true;
                                self.usb_client.receive_packet(app);
                                ReturnCode::SUCCESS
                            }
                        } else {
                            ReturnCode::EINVAL
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_TRANSMIT_OR_RECEIVE => self
                .apps
                .enter(appid, |app, _| {
                    if !app.connected {
                        ReturnCode::ERESERVE
                    } else {
                        if app.is_ready_for_command(Side::TransmitOrReceive) {
                            if app.waiting {
                                ReturnCode::EALREADY
                            } else {
                                // Indicates to the driver that we have a packet to send.
                                let r = self
                                    .usb_client
                                    .transmit_packet(app.buffer.as_ref().unwrap().as_ref(), endpoint);
                                if r != ReturnCode::SUCCESS {
                                    return r;
                                }
                                // Indicates to the driver that we can receive any pending packet.
                                app.waiting = true;
                                self.usb_client.receive_packet(app);

                                ReturnCode::SUCCESS

                            }
                        } else {
                            ReturnCode::EINVAL
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            CTAP_CMD_CANCEL => self
                .apps
                .enter(appid, |app, _| {
                    if !app.connected {
                        ReturnCode::ERESERVE
                    } else {
                        if app.waiting {
                            // FIXME: if cancellation failed, the app should still wait. But that
                            // doesn't work yet.
                            app.waiting = false;
                            if self.usb_client.cancel_transaction(endpoint) {
                                ReturnCode::SUCCESS
                            } else {
                                // Cannot cancel now because the transaction is already in process.
                                // The app should wait for the callback instead.
                                ReturnCode::EBUSY
                            }
                        } else {
                            ReturnCode::EALREADY
                        }
                    }
                })
                .unwrap_or_else(|err| err.into()),
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}
