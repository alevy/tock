// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! RTC driver, nRF5X-family

use core::cell::Cell;
use kernel::ErrorCode;
use kernel::hil::time::{self, Alarm, Ticks, Time};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{ReadOnly, ReadWrite, WriteOnly, register_bitfields};

#[repr(C)]
pub struct RtcRegisters {
    /// Start RTC Counter.
    tasks_start: WriteOnly<u32, Task::Register>,
    /// Stop RTC Counter.
    tasks_stop: WriteOnly<u32, Task::Register>,
    /// Clear RTC Counter.
    tasks_clear: WriteOnly<u32, Task::Register>,
    /// Set COUNTER to 0xFFFFFFF0.
    tasks_trigovrflw: WriteOnly<u32, Task::Register>,
    _reserved0: [u8; 240],
    /// Event on COUNTER increment.
    events_tick: ReadWrite<u32, Event::Register>,
    /// Event on COUNTER overflow.
    events_ovrflw: ReadWrite<u32, Event::Register>,
    _reserved1: [u8; 56],
    /// Compare event on CC\[n\] match.
    events_compare: [ReadWrite<u32, Event::Register>; 4],
    _reserved2: [u8; 436],
    /// Interrupt enable set register.
    intenset: ReadWrite<u32, Inte::Register>,
    /// Interrupt enable clear register.
    intenclr: ReadWrite<u32, Inte::Register>,
    _reserved3: [u8; 52],
    /// Configures event enable routing to PPI for each RTC event.
    evten: ReadWrite<u32, Inte::Register>,
    /// Enable events routing to PPI.
    evtenset: ReadWrite<u32, Inte::Register>,
    /// Disable events routing to PPI.
    evtenclr: ReadWrite<u32, Inte::Register>,
    _reserved4: [u8; 440],
    /// Current COUNTER value.
    counter: ReadOnly<u32, Counter::Register>,
    /// 12-bit prescaler for COUNTER frequency (32768/(PRESCALER+1)).
    /// Must be written when RTC is stopped.
    prescaler: ReadWrite<u32, Prescaler::Register>,
    _reserved5: [u8; 52],
    /// Capture/compare registers.
    cc: [ReadWrite<u32, Counter::Register>; 4],
    _reserved6: [u8; 2732],
    /// Peripheral power control.
    power: ReadWrite<u32>,
}

register_bitfields![u32,
    Inte [
        /// Enable interrupt on TICK event.
        TICK 0,
        /// Enable interrupt on OVRFLW event.
        OVRFLW 1,
        /// Enable interrupt on COMPARE\[0\] event.
        COMPARE0 16,
        /// Enable interrupt on COMPARE\[1\] event.
        COMPARE1 17,
        /// Enable interrupt on COMPARE\[2\] event.
        COMPARE2 18,
        /// Enable interrupt on COMPARE\[3\] event.
        COMPARE3 19
    ],
    Prescaler [
        PRESCALER OFFSET(0) NUMBITS(12)
    ],
    Task [
        ENABLE 0
    ],
    Event [
        READY 0
    ],
    Counter [
        VALUE OFFSET(0) NUMBITS(24)
    ]
];

pub struct Rtc<'a> {
    registers: StaticRef<RtcRegisters>,
    overflow_client: OptionalCell<&'a dyn time::OverflowClient>,
    alarm_client: OptionalCell<&'a dyn time::AlarmClient>,
    enabled: Cell<bool>,
}

impl Rtc<'_> {
    pub const fn new(registers: StaticRef<RtcRegisters>) -> Self {
        Self {
            registers,
            overflow_client: OptionalCell::empty(),
            alarm_client: OptionalCell::empty(),
            enabled: Cell::new(false),
        }
    }

    pub fn handle_interrupt(&self) {
        if self.registers.events_ovrflw.is_set(Event::READY) {
            self.registers.events_ovrflw.write(Event::READY::CLEAR);
            self.overflow_client.map(|client| client.overflow());
        }
        if take_compare0_event(&*self.registers) {
            self.alarm_client.map(|client| {
                client.alarm();
            });
        }
    }
}

/// The subset of the RTC hardware used to implement [`Alarm`] on top of
/// the CC\[0\] compare register.
///
/// The alarm logic ([`set_alarm_hw`], [`take_compare0_event`]) is written
/// against this trait rather than directly against [`RtcRegisters`] so
/// that the exact same code can be exercised on the host against a
/// simulated RTC that models the timing behavior of the real peripheral
/// (see the tests at the bottom of this file).
pub(crate) trait RtcCompareHw {
    /// Read the current (24-bit) COUNTER value.
    fn counter(&self) -> u32;
    /// Read the CC\[0\] register.
    fn cc0(&self) -> u32;
    /// Write the CC\[0\] register.
    fn set_cc0(&self, val: u32);
    /// Whether EVENTS_COMPARE\[0\] is set.
    fn compare0_event(&self) -> bool;
    /// Clear EVENTS_COMPARE\[0\].
    fn clear_compare0_event(&self);
    /// Enable the COMPARE\[0\] interrupt (INTENSET).
    fn enable_compare0_interrupt(&self);
    /// Disable the COMPARE\[0\] interrupt (INTENCLR).
    fn disable_compare0_interrupt(&self);
    /// Whether the COMPARE\[0\] interrupt is enabled.
    fn compare0_interrupt_enabled(&self) -> bool;
}

impl RtcCompareHw for RtcRegisters {
    fn counter(&self) -> u32 {
        self.counter.read(Counter::VALUE)
    }
    fn cc0(&self) -> u32 {
        self.cc[0].read(Counter::VALUE)
    }
    fn set_cc0(&self, val: u32) {
        self.cc[0].write(Counter::VALUE.val(val));
    }
    fn compare0_event(&self) -> bool {
        self.events_compare[0].is_set(Event::READY)
    }
    fn clear_compare0_event(&self) {
        self.events_compare[0].write(Event::READY::CLEAR);
    }
    fn enable_compare0_interrupt(&self) {
        self.intenset.write(Inte::COMPARE0::SET);
    }
    fn disable_compare0_interrupt(&self) {
        self.intenclr.write(Inte::COMPARE0::SET);
    }
    fn compare0_interrupt_enabled(&self) -> bool {
        // Reading INTENSET returns the current interrupt enable state.
        self.intenset.is_set(Inte::COMPARE0)
    }
}

/// Minimum distance (in ticks) between COUNTER and a newly written CC
/// value for the RTC to be guaranteed to generate a COMPARE event.
///
/// From the nRF52832/nRF52840 product specifications (RTC, "Compare"):
/// "If the COUNTER is N, writing N or N+1 to a CC register may not
/// trigger a COMPARE event", whereas "writing N+2 to a CC register is
/// guaranteed to trigger a COMPARE event at N+2".
const MIN_CC_DISTANCE: u32 = 2;

/// Arm CC\[0\] to fire at `reference + dt`, or as soon as possible if
/// that time has already passed (or is too close to `now` to be safely
/// programmed).
///
/// COUNTER cannot be read atomically with the CC write, and keeps
/// ticking (every ~30.5us) while this function runs. If COUNTER
/// increments between the read used to compute the CC value and the CC
/// write itself, the value written may end up being only N+1 (or N)
/// relative to COUNTER at the time of the write, in which case the
/// hardware may *not* generate a COMPARE event. The next match would
/// then only happen after COUNTER wraps around, i.e. 2^24 ticks (512s at
/// 32768Hz) later, stalling every alarm multiplexed on this RTC for up
/// to 8.5 minutes.
///
/// To guard against this we read COUNTER again *after* the write. As
/// COUNTER is monotonic, if it is still at least [`MIN_CC_DISTANCE`]
/// ticks before the programmed value after the write, it was so during
/// the write as well, and the COMPARE event is guaranteed. Otherwise,
/// unless the event has already been generated, we retry with a fresh
/// COUNTER value.
pub(crate) fn set_alarm_hw<H: RtcCompareHw>(hw: &H, reference: time::Ticks24, dt: time::Ticks24) {
    let target = reference.wrapping_add(dt);

    loop {
        let now = time::Ticks24::from(hw.counter());
        let earliest_possible = now.wrapping_add(time::Ticks24::from(MIN_CC_DISTANCE));

        let expire = if !now.within_range(reference, target)
            || target.wrapping_sub(now).into_u32() <= MIN_CC_DISTANCE
        {
            earliest_possible
        } else {
            target
        };

        hw.set_cc0(expire.into_u32());
        hw.clear_compare0_event();
        hw.enable_compare0_interrupt();

        let after = time::Ticks24::from(hw.counter());
        if after.within_range(now, expire)
            && expire.wrapping_sub(after).into_u32() >= MIN_CC_DISTANCE
        {
            // COUNTER was at most `expire - MIN_CC_DISTANCE` when CC was
            // written: the COMPARE event is guaranteed to be generated.
            return;
        }

        if hw.compare0_event() {
            // The COMPARE event was generated anyway, the interrupt will
            // be delivered.
            return;
        }

        // COUNTER advanced too close to (or past) `expire` while we were
        // programming CC, and we cannot tell whether the hardware will
        // generate an event. Try again with an updated COUNTER value.
    }
}

/// If a COMPARE\[0\] event is pending, acknowledge it, disarm the compare
/// interrupt and return `true`.
pub(crate) fn take_compare0_event<H: RtcCompareHw>(hw: &H) -> bool {
    if hw.compare0_event() {
        hw.disable_compare0_interrupt();
        hw.clear_compare0_event();
        true
    } else {
        false
    }
}

impl Time for Rtc<'_> {
    type Frequency = time::Freq32KHz;
    type Ticks = time::Ticks24;

    fn now(&self) -> Self::Ticks {
        Self::Ticks::from(self.registers.counter.read(Counter::VALUE))
    }
}

impl<'a> time::Counter<'a> for Rtc<'a> {
    fn start(&self) -> Result<(), ErrorCode> {
        self.registers.prescaler.write(Prescaler::PRESCALER.val(0));
        self.registers.tasks_start.write(Task::ENABLE::SET);
        self.enabled.set(true);
        Ok(())
    }

    fn stop(&self) -> Result<(), ErrorCode> {
        //self.registers.cc[0].write(Counter::VALUE.val(0));
        self.registers.tasks_stop.write(Task::ENABLE::SET);
        self.enabled.set(false);
        Ok(())
    }

    fn reset(&self) -> Result<(), ErrorCode> {
        self.registers.tasks_clear.write(Task::ENABLE::SET);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.enabled.get()
    }
}

#[allow(deprecated)]
impl<'a> time::CounterOverflow<'a> for Rtc<'a> {
    fn set_overflow_client(&self, client: &'a dyn time::OverflowClient) {
        self.overflow_client.set(client);
        self.registers.intenset.write(Inte::OVRFLW::SET);
    }
}

impl<'a> Alarm<'a> for Rtc<'a> {
    fn set_alarm_client(&self, client: &'a dyn time::AlarmClient) {
        self.alarm_client.set(client);
    }

    fn set_alarm(&self, reference: Self::Ticks, dt: Self::Ticks) {
        set_alarm_hw(&*self.registers, reference, dt);
    }

    fn get_alarm(&self) -> Self::Ticks {
        Self::Ticks::from(self.registers.cc0())
    }

    fn disarm(&self) -> Result<(), ErrorCode> {
        let regs = &*self.registers;
        regs.disable_compare0_interrupt();
        regs.clear_compare0_event();
        Ok(())
    }

    fn is_armed(&self) -> bool {
        // Previously this read EVTEN, which this driver never sets, and
        // therefore always returned `false`.
        self.registers.compare0_interrupt_enabled()
    }

    fn minimum_dt(&self) -> Self::Ticks {
        // TODO: not tested, arbitrary value
        Self::Ticks::from(10)
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests of the RTC alarm logic against a simulated nRF52
    //! RTC.
    //!
    //! The simulator models the RTC COUNTER as a function of CPU time
    //! (64MHz CPU, 32768Hz RTC, so ~1953 CPU cycles per tick). Every
    //! register access costs a few CPU cycles, and is occasionally
    //! delayed further (e.g., by an interrupt). The compare logic follows
    //! the product specification: an event is generated when COUNTER
    //! reaches CC, except that "if the COUNTER is N, writing N or N+1 to a
    //! CC register may not trigger a COMPARE event". The simulator takes
    //! the pessimistic interpretation and never generates an event in that
    //! case (until COUNTER wraps around and matches again).

    extern crate std;

    use super::*;
    use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
    use core::cell::RefCell;
    use kernel::hil::time::{AlarmClient, Ticks24};
    use std::collections::VecDeque;
    use std::vec::Vec;

    const CYCLES_PER_TICK: u64 = 1953;
    const WRAP: u64 = 1 << 24;
    const MASK: u32 = 0x00FF_FFFF;

    /// The pre-fix `Rtc::set_alarm` implementation, verbatim except for
    /// using the `RtcCompareHw` accessors.
    fn legacy_set_alarm_hw<H: RtcCompareHw>(hw: &H, reference: Ticks24, dt: Ticks24) {
        const SYNC_TICS: u32 = 2;
        let mut expire = reference.wrapping_add(dt);
        let now = Ticks24::from(hw.counter());
        let earliest_possible = now.wrapping_add(Ticks24::from(SYNC_TICS));
        if !now.within_range(reference, expire) || expire.wrapping_sub(now).into_u32() <= SYNC_TICS
        {
            expire = earliest_possible;
        }
        hw.set_cc0(expire.into_u32());
        hw.clear_compare0_event();
        hw.enable_compare0_interrupt();
    }

    struct Rng(Cell<u64>);
    impl Rng {
        fn next(&self) -> u64 {
            // xorshift64*
            let mut x = self.0.get();
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0.set(x);
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn range(&self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo)
        }
    }

    struct SimRtc {
        /// Absolute CPU time, in cycles.
        cycles: Cell<u64>,
        cc: Cell<u32>,
        /// The CC value was written when COUNTER was CC-1, so the next
        /// match does not generate an event.
        suppress_next_match: Cell<bool>,
        event: Cell<bool>,
        inten: Cell<bool>,
        rng: Rng,
        /// If non-empty, the cost of the next register accesses (for
        /// deterministic tests). Otherwise costs are random.
        scripted_costs: RefCell<VecDeque<u64>>,
    }

    impl SimRtc {
        fn new(seed: u64) -> Self {
            SimRtc {
                cycles: Cell::new(0),
                cc: Cell::new(0),
                suppress_next_match: Cell::new(false),
                event: Cell::new(false),
                inten: Cell::new(false),
                rng: Rng(Cell::new(seed.wrapping_mul(2).wrapping_add(1))),
                scripted_costs: RefCell::new(VecDeque::new()),
            }
        }

        fn abs_ticks(&self) -> u64 {
            self.cycles.get() / CYCLES_PER_TICK
        }

        /// First absolute tick strictly after `after` at which COUNTER
        /// equals CC.
        fn first_match_after(&self, after: u64) -> u64 {
            let cc = self.cc.get() as u64;
            let next = after + 1;
            next + ((cc + WRAP - (next % WRAP)) % WRAP)
        }

        /// Absolute tick at which the next COMPARE event will be generated
        /// (if the interrupt stays enabled and CC is not rewritten).
        fn next_event_tick(&self) -> Option<u64> {
            if !self.inten.get() {
                return None;
            }
            if self.event.get() {
                return Some(self.abs_ticks());
            }
            let mut t = self.first_match_after(self.abs_ticks());
            if self.suppress_next_match.get() {
                t += WRAP;
            }
            Some(t)
        }

        fn advance_to(&self, to: u64) {
            assert!(to >= self.cycles.get());
            let old = self.abs_ticks();
            self.cycles.set(to);
            let new = self.abs_ticks();
            let mut t = self.first_match_after(old);
            while t <= new {
                if self.suppress_next_match.get() {
                    self.suppress_next_match.set(false);
                } else if self.inten.get() {
                    self.event.set(true);
                }
                t += WRAP;
            }
        }

        /// Account for the CPU time spent until (and including) the next
        /// register access.
        fn access(&self) {
            let cost = self
                .scripted_costs
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| {
                    if self.rng.range(0, 64) == 0 {
                        // Occasionally delayed, e.g., by an interrupt.
                        self.rng.range(50, 1500)
                    } else {
                        self.rng.range(2, 24)
                    }
                });
            self.advance_to(self.cycles.get() + cost);
        }

        fn interrupt_pending(&self) -> bool {
            self.event.get() && self.inten.get()
        }
    }

    impl RtcCompareHw for SimRtc {
        fn counter(&self) -> u32 {
            self.access();
            (self.abs_ticks() % WRAP) as u32
        }
        fn cc0(&self) -> u32 {
            self.access();
            self.cc.get()
        }
        fn set_cc0(&self, val: u32) {
            self.access();
            let counter = (self.abs_ticks() % WRAP) as u32;
            self.cc.set(val & MASK);
            // "If the COUNTER is N, writing N or N+1 to a CC register may
            // not trigger a COMPARE event." Writing N cannot match until
            // the counter wraps anyways; for N+1 we pessimistically
            // suppress the upcoming match.
            self.suppress_next_match
                .set(val.wrapping_sub(counter) & MASK == 1);
        }
        fn compare0_event(&self) -> bool {
            self.access();
            self.event.get()
        }
        fn clear_compare0_event(&self) {
            self.access();
            self.event.set(false);
        }
        fn enable_compare0_interrupt(&self) {
            self.access();
            self.inten.set(true);
        }
        fn disable_compare0_interrupt(&self) {
            self.access();
            self.inten.set(false);
        }
        fn compare0_interrupt_enabled(&self) -> bool {
            self.access();
            self.inten.get()
        }
    }

    /// An `Alarm` implementation over the simulated RTC, using either the
    /// legacy or the current `set_alarm` logic, and the same interrupt
    /// handling logic as `Rtc`.
    struct SimAlarm<'a> {
        hw: SimRtc,
        legacy: bool,
        client: OptionalCell<&'a dyn AlarmClient>,
    }

    impl SimAlarm<'_> {
        fn service_interrupt(&self) {
            if take_compare0_event(&self.hw) {
                self.client.map(|c| c.alarm());
            }
        }
    }

    impl Time for SimAlarm<'_> {
        type Frequency = time::Freq32KHz;
        type Ticks = Ticks24;
        fn now(&self) -> Ticks24 {
            Ticks24::from(self.hw.counter())
        }
    }

    impl<'a> Alarm<'a> for SimAlarm<'a> {
        fn set_alarm_client(&self, client: &'a dyn AlarmClient) {
            self.client.set(client);
        }
        fn set_alarm(&self, reference: Ticks24, dt: Ticks24) {
            if self.legacy {
                legacy_set_alarm_hw(&self.hw, reference, dt)
            } else {
                set_alarm_hw(&self.hw, reference, dt)
            }
        }
        fn get_alarm(&self) -> Ticks24 {
            Ticks24::from(self.hw.cc0())
        }
        fn disarm(&self) -> Result<(), ErrorCode> {
            self.hw.disable_compare0_interrupt();
            self.hw.clear_compare0_event();
            Ok(())
        }
        fn is_armed(&self) -> bool {
            self.hw.compare0_interrupt_enabled()
        }
        fn minimum_dt(&self) -> Ticks24 {
            Ticks24::from(10)
        }
    }

    /// Set up the CC write race.
    ///
    /// Positions the simulated CPU clock just before a COUNTER increment,
    /// and scripts the next register accesses such that COUNTER increments
    /// between the COUNTER read and the CC write in `set_alarm`.
    fn setup_race(alarm: &SimAlarm, start_tick: u64) {
        alarm.hw.cycles.set((start_tick + 1) * CYCLES_PER_TICK - 10);
        // COUNTER read lands before the increment (N), CC write after it
        // (N+1), all other accesses are cheap.
        alarm
            .hw
            .scripted_costs
            .borrow_mut()
            .extend([4, 20, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]);
    }

    /// Distilled reproduction of the lost COMPARE event.
    ///
    /// Arm an alarm that has already expired (as the virtual alarm mux does whenever an alarm
    /// expired while it was processing others). The legacy driver programs
    /// CC = COUNTER + 2 based on a COUNTER value that is stale by one tick
    /// at the time of the CC write, and no event is generated until COUNTER
    /// wraps around 2^24 ticks (~512s) later.
    #[test]
    fn legacy_set_alarm_loses_compare_event_on_counter_increment() {
        let alarm = SimAlarm {
            hw: SimRtc::new(1),
            legacy: true,
            client: OptionalCell::empty(),
        };
        setup_race(&alarm, 1000);
        // Alarm that expired 5 ticks ago.
        alarm.set_alarm(Ticks24::from(900), Ticks24::from(95));
        let armed_at = alarm.hw.abs_ticks();
        let fires_at = alarm.hw.next_event_tick().unwrap();
        assert_eq!(
            fires_at - armed_at,
            WRAP + 1,
            "expected the alarm to be delayed by a full counter wrap"
        );
    }

    #[test]
    fn set_alarm_survives_counter_increment_during_cc_write() {
        let alarm = SimAlarm {
            hw: SimRtc::new(1),
            legacy: false,
            client: OptionalCell::empty(),
        };
        setup_race(&alarm, 1000);
        alarm.set_alarm(Ticks24::from(900), Ticks24::from(95));
        let armed_at = alarm.hw.abs_ticks();
        let fires_at = alarm.hw.next_event_tick().unwrap();
        assert!(
            fires_at - armed_at <= MIN_CC_DISTANCE as u64 + 1,
            "alarm delayed by {} ticks",
            fires_at - armed_at
        );
    }

    /// Exhaustively check alarms close to expiry.
    ///
    /// For every position of the CPU clock within a tick and for alarms
    /// expiring from the past up to a few ticks in the future, the alarm
    /// must fire no later than `max(expiry, now) + 3` ticks.
    #[test]
    fn set_alarm_never_misses_near_expiry() {
        for phase in (0..CYCLES_PER_TICK).step_by(7) {
            for remaining in -4i64..8 {
                for delay in [4u64, 20, 60, 400, 2500] {
                    let alarm = SimAlarm {
                        hw: SimRtc::new(1),
                        legacy: false,
                        client: OptionalCell::empty(),
                    };
                    let start_tick = 5000u64;
                    alarm.hw.cycles.set(start_tick * CYCLES_PER_TICK + phase);
                    alarm
                        .hw
                        .scripted_costs
                        .borrow_mut()
                        .extend([4, delay, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]);
                    let reference = Ticks24::from((start_tick - 100) as u32);
                    let dt = Ticks24::from((100 + remaining) as u32);
                    alarm.set_alarm(reference, dt);
                    let expiry = (start_tick as i64 + remaining) as u64;
                    let fires_at = alarm.hw.next_event_tick().unwrap();
                    let bound = core::cmp::max(expiry, alarm.hw.abs_ticks()) + 3;
                    assert!(
                        fires_at <= bound,
                        "phase {} remaining {} delay {}: fires at {}, bound {}",
                        phase,
                        remaining,
                        delay,
                        fires_at,
                        bound
                    );
                }
            }
        }
    }

    /// A virtual alarm client that re-arms itself and records how late it
    /// fired relative to the requested expiration.
    struct Client<'a> {
        name: &'static str,
        valarm: &'a VirtualMuxAlarm<'a, SimAlarm<'a>>,
        hw: &'a SimRtc,
        /// Absolute tick at which the outstanding alarm should fire.
        expected: Cell<Option<u64>>,
        /// Max lateness (ticks) observed at firing time.
        max_late: Cell<u64>,
        fires: Cell<u64>,
        /// Number of times this alarm fired more than 1s late.
        late_fires: Cell<u64>,
        /// If set, model an application: after the alarm fires, wake up
        /// after some processing latency and re-arm with a reference read
        /// at wakeup time. Otherwise, model an in-kernel client (like the
        /// SEGGER RTT receive poller) that re-arms from its callback.
        app: bool,
        period: u32,
        wake_at: Cell<Option<u64>>,
    }

    impl Client<'_> {
        fn arm(&self, dt: u32) {
            let reference = self.valarm.now();
            let abs = self.hw.abs_ticks();
            // Model the time between reading `now` and arming (e.g. the
            // syscall path for an app).
            self.hw.access();
            self.valarm.set_alarm(reference, Ticks24::from(dt));
            self.expected.set(Some(abs + dt as u64));
        }

        fn app_wakeup(&self) {
            self.wake_at.set(None);
            let rng = &self.hw.rng;
            // lvgl-like: mostly display refresh periods, sometimes very
            // short, sometimes a full second.
            let dt = match rng.range(0, 10) {
                0 => rng.range(1, 40) as u32,
                1 => self.period,
                _ => rng.range(30, 1100) as u32,
            };
            self.arm(dt);
        }

        fn overdue(&self, now_tick: u64) -> u64 {
            self.expected
                .get()
                .map_or(0, |e| now_tick.saturating_sub(e))
        }
    }

    impl AlarmClient for Client<'_> {
        fn alarm(&self) {
            let now = self.hw.abs_ticks();
            let expected = self.expected.take().expect("spurious alarm");
            assert!(now >= expected, "{} fired early", self.name);
            self.max_late
                .set(core::cmp::max(self.max_late.get(), now - expected));
            self.fires.set(self.fires.get() + 1);
            if now - expected > 32768 {
                self.late_fires.set(self.late_fires.get() + 1);
            }
            if self.app {
                // Process scheduling + lvgl rendering latency: 0.1ms-25ms.
                let latency = self.hw.rng.range(200_000 / 30, 25 * 64_000);
                self.wake_at.set(Some(self.hw.cycles.get() + latency));
            } else {
                self.arm(self.period);
            }
        }
    }

    struct SimResult {
        /// Max lateness (ticks) of any alarm, observed while running.
        max_overdue: u64,
        /// Simulated time (seconds) at which an alarm first became overdue
        /// by more than 1s, if any.
        first_stall_s: Option<f64>,
        fires: u64,
        /// Number of times the app's alarm fired more than 1s late.
        app_stalls: u64,
    }

    /// Run a sma_q3-like configuration.
    ///
    /// A single RTC is multiplexed between
    /// the SEGGER RTT receive poller (re-arming every 100ms from its
    /// callback), and an application (through the alarm syscall driver)
    /// re-arming after rendering with lvgl-like delays.
    fn simulate(legacy: bool, seed: u64, seconds: u64, stop_on_stall: bool) -> SimResult {
        let alarm = SimAlarm {
            hw: SimRtc::new(seed),
            legacy,
            client: OptionalCell::empty(),
        };
        // Start at a random point in the counter range.
        alarm
            .hw
            .cycles
            .set(alarm.hw.rng.range(0, WRAP) * CYCLES_PER_TICK);
        let mux = MuxAlarm::new(&alarm);
        alarm.set_alarm_client(&mux);

        let v_rtt = VirtualMuxAlarm::new(&mux);
        v_rtt.setup();
        let v_app = VirtualMuxAlarm::new(&mux);
        v_app.setup();

        let rtt = Client {
            name: "rtt",
            valarm: &v_rtt,
            hw: &alarm.hw,
            expected: Cell::new(None),
            max_late: Cell::new(0),
            fires: Cell::new(0),
            late_fires: Cell::new(0),
            app: false,
            period: 3277, // 100ms
            wake_at: Cell::new(None),
        };
        let app = Client {
            name: "app",
            valarm: &v_app,
            hw: &alarm.hw,
            expected: Cell::new(None),
            max_late: Cell::new(0),
            fires: Cell::new(0),
            late_fires: Cell::new(0),
            app: true,
            period: 32768, // 1s
            wake_at: Cell::new(None),
        };
        v_rtt.set_alarm_client(&rtt);
        v_app.set_alarm_client(&app);

        rtt.arm(rtt.period);
        app.arm(app.period);

        let end = alarm.hw.cycles.get() + seconds * 32768 * CYCLES_PER_TICK;
        let mut max_overdue = 0;
        let mut first_stall_s = None;
        let start = alarm.hw.cycles.get();

        while alarm.hw.cycles.get() < end {
            if alarm.hw.interrupt_pending() {
                // Interrupt latency until the kernel loop services the RTC.
                let latency = alarm.hw.rng.range(30, 600);
                alarm.hw.advance_to(alarm.hw.cycles.get() + latency);
                alarm.service_interrupt();
                continue;
            }

            let mut next = end;
            if let Some(t) = alarm.hw.next_event_tick() {
                next = core::cmp::min(next, t * CYCLES_PER_TICK);
            }
            if let Some(w) = app.wake_at.get() {
                next = core::cmp::min(next, w);
            }
            let next = core::cmp::max(next, alarm.hw.cycles.get());

            let next_tick = next / CYCLES_PER_TICK;
            let overdue = core::cmp::max(rtt.overdue(next_tick), app.overdue(next_tick));
            if overdue > max_overdue {
                max_overdue = overdue;
            }
            if overdue > 32768 && first_stall_s.is_none() {
                // Report when the stall started.
                let stall_start =
                    (next_tick - overdue) * CYCLES_PER_TICK - core::cmp::min(start, next);
                first_stall_s = Some(stall_start as f64 / (32768.0 * CYCLES_PER_TICK as f64));
                if stop_on_stall {
                    break;
                }
            }

            alarm.hw.advance_to(next);
            if app
                .wake_at
                .get()
                .is_some_and(|w| w <= alarm.hw.cycles.get())
            {
                app.app_wakeup();
            }
        }

        SimResult {
            max_overdue: max_overdue.max(rtt.max_late.get()).max(app.max_late.get()),
            first_stall_s,
            fires: rtt.fires.get() + app.fires.get(),
            app_stalls: app.late_fires.get(),
        }
    }

    /// End-to-end reproduction of the stall.
    ///
    /// With the legacy driver, the sma_q3-like configuration eventually loses a COMPARE event, and *every* alarm
    /// multiplexed on the RTC (including the app's) stalls for a full
    /// counter wrap (~512s).
    ///
    /// Note that the virtual alarm mux does not recover from the lost
    /// event: as the currently programmed hardware alarm appears to have
    /// expired, it assumes that an interrupt is pending and does not
    /// reprogram the hardware when new alarms are set.
    #[test]
    fn legacy_driver_stalls_all_alarms_for_a_counter_wrap() {
        let mut stalls = Vec::new();
        for seed in 1..=8 {
            let r = simulate(true, seed, 6 * 3600, true);
            if let Some(t) = r.first_stall_s {
                stalls.push((seed, t, r.max_overdue));
            }
        }
        std::println!(
            "legacy stalls (seed, start [s], overdue [ticks]): {:?}",
            stalls
        );
        assert!(!stalls.is_empty(), "expected the legacy driver to stall");
    }

    /// Estimate how often the legacy driver stalls (run with
    /// `cargo test --release -- --ignored --nocapture`).
    #[test]
    #[ignore = "slow; for estimating the stall rate"]
    fn legacy_driver_stall_rate() {
        for seed in 1..=4 {
            let r = simulate(true, seed, 24 * 3600, false);
            std::println!(
                "seed {}: {} app stalls of ~512s in 24h ({} alarms fired)",
                seed,
                r.app_stalls,
                r.fires
            );
        }
    }

    /// The same configuration with the fixed driver never stalls.
    #[test]
    fn fixed_driver_never_stalls() {
        for seed in 1..=8 {
            let r = simulate(false, seed, 6 * 3600, false);
            std::println!(
                "seed {}: {} alarms fired, max lateness {} ticks",
                seed,
                r.fires,
                r.max_overdue
            );
            assert!(
                r.max_overdue < 64,
                "seed {}: alarm late by {} ticks (stall started at {:?}s)",
                seed,
                r.max_overdue,
                r.first_stall_s
            );
        }
    }
}
