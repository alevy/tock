//! System call driver for getting real time

use core::{cell::Cell, str::FromStr};

use kernel::{grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount}, hil::{date_time::DateTimeClient, time::{Ticks, Time}}, syscall::{CommandReturn, SyscallDriver}, ErrorCode, ProcessId};

/// TODO
#[derive(Debug)]
pub struct Timestamp {
    /// TODO
    pub hour: u8,
    /// TODO
    pub minute: u8,
    /// TODO
    pub milliseconds: u16,
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

/// TODO
#[derive(Debug)]
pub struct Date {
    /// TODO
    pub day: u8,
    /// TODO
    pub month: u8,
    /// TODO
    pub year: u8,
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
pub trait Datetime {
    fn set_client(&'a kernel::hil::date_time::DateTimeClient);
    /// TODO
    fn start(&self) -> Result<(), ErrorCode>;
}

impl Datetime for () {
    fn start(&self) -> Result<(), ErrorCode> {
        Ok(())
    }
}

/// TODO
pub trait DatetimeClient {
    /// TODO
    fn datetime_available(&self, date: Date, time: Timestamp);
}

#[derive(Default)]
/// TODO
pub struct App {
    waiting_for_time: bool,
}

/// TODO
pub struct Realtime<'a, A: Time, D: Datetime> {
    running: Cell<bool>,
    grant: Grant<App, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<0>>,
    alarm: &'a A,
    driver: &'a D,
}

impl<'a, A: Time, D: Datetime> Realtime<'a, A, D> {
    /// TODO
    pub fn new(driver: &'a D, alarm: &'a A, grant: Grant<App, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<0>>) -> Self {
	Self {
	    running: Cell::new(false),
	    grant,
	    alarm,
	    driver
	}
    }

    fn enqueue_get_time_once(&self, process_id: ProcessId) -> CommandReturn {
	self.grant.enter(process_id, |grant, _| {
	    grant.waiting_for_time = true;
	    if !self.running.get() {
		self.running.set(true);
		match self.driver.start() {
		    Ok(()) => CommandReturn::success(),
		    Err(e) => CommandReturn::failure(e),
		}
	    } else {
		CommandReturn::success()
	    }
	}).unwrap_or_else(|e| CommandReturn::failure(e.into()))
    }
}

impl<'a, A: Time, D: Datetime> DatetimeClient for Realtime<'a, A, D> {
    fn datetime_available(&self, date: Date, time: Timestamp) {
        for app in self.grant.iter() {
	    app.enter(|grant, upcalls| {
		if grant.waiting_for_time {
		    grant.waiting_for_time = false;
		    let date = ((date.year as u32) << 16) | ((date.month as u32) << 8) | (date.day as u32);
		    let time = ((time.hour as u32) << 24) | ((time.minute as u32) << 16) | (time.milliseconds as u32);
		    let reference = self.alarm.now().into_u32_left_justified();
		    upcalls.schedule_upcall(0, (date as usize, time as usize, reference as usize)).ok();
		}
	    });
	}
    }
}

impl<'a, A: Time, D: Datetime> SyscallDriver for Realtime<'a, A, D> {
    fn command(
        &self,
        command_num: usize,
        _r2: usize,
        _r3: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
	match command_num {
	    0 => CommandReturn::success(),
            1 => self.enqueue_get_time_once(process_id),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
	}
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
	self.grant.enter(process_id, |_, _| ())
    }
}
