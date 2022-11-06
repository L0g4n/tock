#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Transmit,
    Receive,
    TransmitOrReceive,
}

impl Side {
    pub fn can_transmit(&self) -> bool {
        match self {
            Side::Transmit | Side::TransmitOrReceive => true,
            Side::Receive => false,
        }
    }

    pub fn can_receive(&self) -> bool {
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
    pub connected: bool,
    // Currently enabled transaction side. Subscribing to a callback or allowing a buffer
    // automatically sets the corresponding side. Clearing both the callback and the buffer resets
    // the side to None.
    pub side: Option<Side>,
    // Whether the app is waiting for the kernel signaling a packet transfer.
    pub waiting: bool,
}

impl App {
    pub fn can_receive_packet(&self) -> bool {
        self.waiting && self.side.map_or(false, |side| side.can_receive())
    }

    pub fn check_side(&mut self) {
        if !self.waiting {
            self.side = None;
        }
    }

    pub fn set_side(&mut self, side: Side) -> bool {
        match self.side {
            None => {
                self.side = Some(side);
                true
            }
            Some(app_side) => side == app_side,
        }
    }

    pub fn is_ready_for_command(&self, side: Side) -> bool {
        self.side == Some(side)
    }
}
