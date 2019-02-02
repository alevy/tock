use kernel::debug;
use core::cell::Cell;
use kernel::common::cells::TakeCell;
use kernel::hil::gpio;
use kernel::hil::spi;

pub static mut FRAME_BUFFER: [u8; 5000] = [0; 5000]; 

static INIT_CMDS: [(u8, u8, [u8;4]); 10] = [
    (0x01, 3, [0xC7, 0, 0, 0]),
    (0x0c, 3, [0xD7, 0xD6, 0x9D, 0]),
    (0x2c, 1, [0xa8, 0, 0, 0]),
    (0x3a, 1, [0x1a, 0, 0, 0]),
    (0x3b, 1, [0x08, 0, 0, 0]),
    (0x11, 1, [0x01, 0, 0, 0]),
    (0x44, 2, [0x0, 0x18, 0, 0]),
    (0x45, 4, [0xc7, 0x0, 0x0, 0x0]),
    (0x4e, 1, [0x0, 0, 0, 0]),
    (0x4f, 2, [0xc7, 0x0, 0, 0]),
];

static UPDATE_CMDS: [(u8, u8, [u8; 1]); 3] = [
    (0x22, 1, [0x4]),
    (0x22, 1, [0x8]),
    (0x22, 1, [0xc7]),
];

#[derive(Copy, Clone, Debug)]
enum State {
    Idle,
    Initializing(usize, bool),
    Write,
    Update,
}

pub struct Epd<'a, S: spi::SpiMaster, G: gpio::Pin> {
    spi: &'a S,
    cs: S::ChipSelect,
    reset: &'a G,
    dc: &'a G,
    buf: TakeCell<'static, [u8]>, 
    state: Cell<State>,
}

impl<'a, S: spi::SpiMaster, G: gpio::Pin> Epd<'a, S, G> {
    pub fn new(spi: &'a S, reset: &'a G, dc: &'a G, cs: S::ChipSelect, buf: &'static mut [u8]) -> Self {
        Epd {
            spi,
            cs,
            reset,
            dc,
            buf: TakeCell::new(buf),
            state: Cell::new(State::Idle),
        }
    }

    pub fn initialize(&self) {
        self.spi.init();
        self.reset.set();
        self.dc.clear();
        for _ in 0..1000 {
            self.reset.set();
        }

        self.state.set(State::Initializing(0, false));
        self.reset.clear();
        self.dc.clear();
        self.spi.specify_chip_select(self.cs);

        self.buf.take().map(|buf| {
            buf[0] = INIT_CMDS[0].0;
            self.spi.read_write_bytes(buf, None, 1);
        });
    }
}

impl<'a, S: spi::SpiMaster, G: gpio::Pin> spi::SpiMasterClient for Epd<'a, S, G> {
    fn read_write_done(&self, buf: &'static mut [u8], _: Option<&'static mut [u8]>, len: usize) {
        let state = self.state.get();
        //debug!("{:?} ({}): Transferred {}", state, INIT_CMDS.len(), len);

        match state {
            State::Initializing(stage, data) => {
                if stage >= INIT_CMDS.len() {
                    self.dc.clear();
                    buf[0] = 0x24; // Write to DATA RAM
                    self.spi.read_write_bytes(buf, None, 1);
                    self.state.set(State::Write);
                } else if !data {
                    self.dc.set();
                    self.state.set(State::Initializing(stage, true));
                    let cmd = INIT_CMDS[stage];
                    buf[0] = cmd.2[0];
                    buf[1] = cmd.2[1];
                    buf[2] = cmd.2[2];
                    buf[3] = cmd.2[3];
                    self.spi.read_write_bytes(buf, None, cmd.1 as usize);
                } else if stage + 1 < INIT_CMDS.len() {
                    self.dc.clear();
                    self.state.set(State::Initializing(stage + 1, false));
                    //debug!("{}/{}", stage, INIT_CMDS.len());
                    buf[0] = INIT_CMDS[stage + 1].0;
                    self.spi.read_write_bytes(buf, None, 1);
                } else {
                    debug!("Initialized");
                    buf[0] = 0x24; // Write to DATA RAM
                    self.spi.read_write_bytes(buf, None, 1);
                    self.state.set(State::Write);
                }
            },
            State::Write => {
                self.dc.set();
                self.spi.read_write_bytes(buf, None, buf.len());
                self.state.set(State::Update);
            },
            State::Update => {
                self.dc.clear();
                buf[0] = 0x20;
                self.spi.read_write_bytes(buf, None, 1);
                self.state.set(State::Idle);
            },
            State::Idle => {
                debug!("Done");
            },
        }
    }
}

