use kernel::common::cells::OptionalCell;
use std::time::{Duration, SystemTime};
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use crate::chip;

pub struct UnixAlarm<'a> {
    client: OptionalCell<&'a kernel::hil::time::Client>,
    event_sender: Arc<Mutex<Option<Sender<chip::Event>>>>,
}

impl<'a> UnixAlarm<'a> {
    pub fn new(event_sender: Sender<chip::Event>) -> Self {
        UnixAlarm {
            client: OptionalCell::empty(),
            event_sender: Arc::new(Mutex::new(Some(event_sender))),
        }
    }

    pub fn set_client(&self, client: &'static kernel::hil::time::Client) {
        self.client.set(client);
    }

    pub fn handle_interrupt(&self) {
        self.client.map(|client| {
            client.fired()
        });
    }
}

impl<'a> kernel::hil::time::Time for UnixAlarm<'a> {
    type Frequency = kernel::hil::time::Freq1MHz;

    fn disable(&self) {}

    fn is_armed(&self) -> bool { true }
}

impl<'a> kernel::hil::time::Alarm for UnixAlarm<'a> {

    fn now(&self) -> u32 {
        if let Ok(duration) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            (duration.as_secs() * 1000 + duration.subsec_millis() as u64) as u32
        } else {
            0 // there was an error, not sure why there would be...
        }
    }

    fn set_alarm(&self, tics: u32) {
        let target = Duration::from_millis(tics.wrapping_sub(self.now()) as u64);
        let sender = self.event_sender.clone();
        thread::spawn(move || {
            thread::sleep(target);
            sender.lock().map(|m| m.as_ref().map(|sender| sender.send(chip::Event::Alarm))).unwrap();
        });
    }

    fn get_alarm(&self) -> u32 {
        0
    }

}
