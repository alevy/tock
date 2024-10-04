use core::{cell::Cell, str::FromStr};

use kernel::{hil::{date_time::{DateTime, DateTimeClient, DateTimeValues, Month}, gpio::Output, uart::{Receive, ReceiveClient}}, utilities::cells::{OptionalCell, TakeCell}};

#[derive(Debug)]
struct Timestamp {
    hour: u8,
    minute: u8,
    milliseconds: u16,
}

impl FromStr for Timestamp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
	let hour = s.get(0..2).unwrap_or("").parse().map_err(|_| ())?;
	let minute = s.get(2..4).unwrap_or("").parse().map_err(|_| ())?;
	let milliseconds: f32 = s.get(4..).unwrap_or("").parse().map_err(|_| ())?;
	let milliseconds = (milliseconds * 1000.0) as u16;
	Ok(Timestamp {
	    hour,
	    minute,
	    milliseconds,
	})
    }
}

#[derive(Debug)]
struct Date {
    day: u8,
    month: u8,
    year: u8,
}

impl FromStr for Date {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
	let day = s.get(0..2).unwrap_or("").parse().map_err(|_| ())?;
	let month = s.get(2..4).unwrap_or("").parse().map_err(|_| ())?;
	let year = s.get(4..6).unwrap_or("").parse().map_err(|_| ())?;
	Ok(Date {
	    day,
	    month,
	    year,
	})
    }
}

/// TODO
pub struct GNSS<'a, U, Pin> {
    client: OptionalCell<&'a dyn DateTimeClient>,
    rx_buffer: TakeCell<'static, [u8]>,
    buffer: Cell<[u8; 79]>,
    offset: Cell<usize>,
    uart: &'a U,
    power: &'a Pin,
}

impl<'a, U: Receive<'a>, P> GNSS<'a, U, P> {
    /// TODO
    pub fn new(uart: &'a U, power: &'a P, rx_buffer: &'static mut [u8]) -> Self {
	Self {
	    client: OptionalCell::empty(),
	    rx_buffer: TakeCell::new(rx_buffer),
	    buffer: Cell::new([0; 79]),
	    offset: Cell::new(0),
	    uart,
	    power,
	}
    }
}

fn parse_line(line: &[u8]) -> Option<(Timestamp, Date)> {
    let mut components = core::str::from_utf8(line).ok()?.split(',');

    let cmd = components.next()?;
    if let (_, "RMC") = cmd.split_at_checked(2)? {
	let utc = components.next()?;
	let status = components.next()?;
	let lat_degrees = components.next()?;
	let lat_ns = components.next()?;
	let lon_degrees = components.next()?;
	let lon_ew = components.next()?;
	let sog = components.next()?;
	let cog = components.next()?;
	let date = components.next()?;
	let magnetic_var = components.next()?;
	let magnetic_var_ew = components.next()?;
	let mode = components.next()?;
	let cs = components.next()?;
	utc.parse().ok().zip(date.parse().ok())
    } else {
	None
    }
}

impl<'a, U: Receive<'a>, P: Output> ReceiveClient for GNSS<'a, U, P> {
    fn received_buffer(
	&self,
	rx_buffer: &'static mut [u8],
	_rx_len: usize,
	_rval: Result<(), kernel::ErrorCode>,
	_error: kernel::hil::uart::Error,
    ) {
	let done = match rx_buffer[0] {
	    b'\n' | b'\r' => {
		let offset = self.offset.get();
		if offset > 0 {
		    self.offset.set(0);
		    if let Some((t, d)) = parse_line(&self.buffer.get()[..offset]) {
			self.power.clear();
			self.client.map(|client| {
			    let dtv = DateTimeValues {
				year: d.year as u16 + 2000,
				month: match d.month {
				    1 => Month::January,
				    2 => Month::February,
				    3 => Month::March,
				    4 => Month::April,
				    5 => Month::May,
				    6 => Month::June,
				    7 => Month::July,
				    8 => Month::August,
				    9 => Month::September,
				    10 => Month::October,
				    11 => Month::November,
				    12 => Month::December,
				    _ => Month::January,
				},
				day: d.day,
				day_of_week: kernel::hil::date_time::DayOfWeek::Monday,
				hour: t.hour,
				minute: t.minute,
				seconds: (t.milliseconds / 1000) as u8,
			    };
			    client.get_date_time_done(Ok(dtv));
			});
			true
		    } else {
			false
		    }
		} else {
		    false
		}
	    },
	    b'$' | b'!' => {
		self.offset.set(0);
		false
	    },
	    c => {
		self.buffer.as_array_of_cells()[self.offset.get()].set(c);
		self.offset.set(self.offset.get() + 1);
		false
	    }
	};

	if done {
	    self.rx_buffer.replace(rx_buffer);
	} else {
	    self.uart.receive_buffer(rx_buffer, rx_buffer.len()).unwrap();
	}
    }
}

impl<'a, U: Receive<'a>, P: Output> DateTime<'a> for GNSS<'a, U, P> {
    fn get_date_time(&self) -> Result<(), kernel::ErrorCode> {
	if let Some(buf) = self.rx_buffer.take() {
	    self.power.set();
	    self.uart.receive_buffer(buf, 1).unwrap();
	    Ok(())
	} else {
	    Ok(())
	}

    }

    fn set_date_time(&self, date_time: kernel::hil::date_time::DateTimeValues) -> Result<(), kernel::ErrorCode> {
        Err(kernel::ErrorCode::NOSUPPORT)
    }

    fn set_client(&self, client: &'a dyn kernel::hil::date_time::DateTimeClient) {
        self.client.set(client)
    }
}
