# BLE Peripheral / Connected-Mode Support — Working Notes

Status as of commit `43c60282` on branch
`claude/nrf52-ble-connected-channels-xho3y4`.

This document is a hand-off for picking this work back up in a fresh session
(or by another person). It covers **what works, where the code lives, the
sequence of bugs we hit and how we fixed them, the known outstanding tasks, and
the multi-chip / HIL-evaluation question**. It assumes familiarity with the BLE
stack at a high level; the "Layering" section gives the map we settled on.

---

## 1. What works today (observed, on hardware)

On an **nRF52840-DK**, with the userspace BLE syscall driver effectively unused,
the board boots straight into connectable advertising and supports a full
peripheral session against a Linux central (BlueZ / `bluetoothctl`):

- Advertises `ADV_IND` ("TockBLE", addr `C0:FF:EE:BE:EF:42`) on ch 37/38/39.
- Accepts `CONNECT_IND`, establishes an LE connection.
- Link layer: channel hopping (CSA#1), window widening, SN/NESN
  acknowledgement, stop-and-wait retransmission, supervision timeout.
- Completes the LL control handshake (`LL_FEATURE_REQ`→`RSP`,
  `LL_VERSION_IND`, `LL_UNKNOWN_RSP` for the rest).
- Completes GATT discovery and exposes one vendor service (`0xFFF0`) with one
  **read/write characteristic** (`0xFFF1`, default value `DE AD BE EF`).
- **Read and write of the characteristic round-trip correctly** from
  `bluetoothctl`.
- Holds an idle connection indefinitely; tears down cleanly on
  `LL_TERMINATE_IND` and resumes advertising.

The connection has been held for thousands of connection events (minutes)
without dropping.

**Not yet working / not done:** SCAN_RSP (so the device does *not* reliably
appear in nRF Connect on Android), notifications, applying master-initiated
connection/channel-map updates, MTU > 23 / fragmentation, and the whole thing
is a single capsule that violates layering (see §5 and §6).

---

## 2. How to build & test

```sh
# Build (from the board dir, which has the required .cargo/config sentinel):
cd boards/nordic/nrf52840dk
cargo check --target thumbv7em-none-eabihf
cargo clippy --target thumbv7em-none-eabihf     # branch is kept clippy-clean
# flash: your usual `make flash` / probe-rs / JTAG for this board.
```

Debug output (the diagnostic dumps, see §7) goes to the **UART console**
(`USB_DEBUGGING = false` in the board `lib.rs`), same place as `debug!`.

`bluetoothctl` session that exercises everything:

```
connect C0:FF:EE:BE:EF:42
menu gatt
list-attributes C0:FF:EE:BE:EF:42          # shows service fff0 / char fff1
select-attribute <path to char fff1>
read                                        # -> de ad be ef
write "0x01 0x02 0x03"
read                                        # -> 01 02 03
disconnect                                  # peripheral resumes advertising
```

---

## 3. Where the code lives (file map)

| File | Layer | What it contains |
|------|-------|------------------|
| `chips/nrf52/src/ble_radio.rs` | PHY + LL (controller, **timing-critical**, chip-specific) | Raw radio control; connection-event hardware sequence via TIMER0 + PPI + SHORTS; hardware RX→TX turnaround at T_IFS; SN/NESN stamping + "empty-on-ack" in the ISR; `connection_configure` / `connection_event_start` / `get_timer0_now`. |
| `kernel/src/hil/ble_advertising.rs` | HIL | `BleAdvertisementDriver`, `BleConfig`, `RxClient`, `TxClient` (pre-existing advertising HIL) **plus** the connection additions: `ConnectionParams`, `BleConnectionDriver`, `ConnectionEventClient`, `ConnectionSetupClient`, and `RadioChannel` data-channel helpers. |
| `capsules/extra/src/ble_advertising_driver.rs` | LL (advertising) + syscall driver | The existing userspace advertising syscall driver, extended with **kernel-mode** connectable advertising: `start_connectable_advertising()`, `set_connection_driver()`, CONNECT_IND parse + hand-off, and `DisconnectClient` impl that resumes advertising when a connection ends. |
| `capsules/extra/src/ble_ll_connection.rs` | LL (connection) + L2CAP + ATT + GATT — **currently all in one capsule (layering violation, see §6)** | `ConnectionManager`: connection state machine, CSA#1 hopping, window widening, anchor tracking, supervision timeout, coarse-alarm scheduling; stop-and-wait TX flow control + response queue; LL control-PDU responses; L2CAP demux; a minimal ATT server; a minimal GATT attribute table; diagnostic ring buffers. |
| `boards/nordic/nrf52840dk/src/lib.rs` | board wiring | `static_init!`s the `ConnectionManager`, wires it to the radio and the advertising capsule, and calls `start_connectable_advertising()` at boot. |

Key wiring in the board (search for `conn_manager` / `start_connectable_advertising`):

```rust
ble_radio.set_connection_driver(&base_peripherals.ble_radio, conn_manager);
conn_manager.set_disconnect_client(ble_radio);
ble_radio.start_connectable_advertising();
```

---

## 4. The controller / host split and hardware timing

The BLE stack, and where each part sits:

```
 Host    GATT   (services / characteristics semantics)   ── portable, NOT timing-sensitive
         ATT    (attribute PDUs: Read/Write/Notify…)
         SMP / L2CAP-signalling
         L2CAP  (multiplex by CID; +seg/flow for CoC only)
 ─────────────────────────────────────────────────────
 Ctrlr   Link Layer (conn, SN/NESN, hopping, ctrl PDUs)  ── TIMING-CRITICAL
         Physical Layer (radio)
```

Facts that shaped the design:

- **Only the Link Layer is timing-critical.** The response to a master packet
  must go out exactly T_IFS = 150 µs later. On the nRF52 this is done entirely
  in **hardware**: PPI wires TIMER0 compares to RADIO tasks, and SHORTS
  (`READY_START | END_DISABLE | DISABLED_TXEN`) drive RX→TX with the `TIFS`
  register enforcing the 150 µs gap. The CPU only sets TIMER0.CC[0] between
  events and fixes up the pre-loaded TX PDU header (SN/NESN) during the ~40 µs
  TX-ramp window in the DISABLED ISR.
- **Everything above L2CAP is latency-tolerant and portable** — it does not
  touch the chip. Our ATT/GATT code runs in a capsule at leisure.
- **CID `0x0004` is ATT.** GATT sits on ATT, ATT on the fixed L2CAP channel
  `0x0004`. On LE the fixed channels are thin (4-byte L2CAP header, no
  L2CAP-level segmentation — fragmentation is at the LL via the continuation
  LLID `0b01`). MTU 23 is special because 23 + 4 (L2CAP header) = 27 = the
  default max LL data-PDU payload, i.e. "fits in one packet, no fragmentation."
  The genuine stream/flow-control behaviour of L2CAP is the connection-oriented
  channel (CoC) feature on **dynamic** CIDs (`0x0040+`), which we do **not**
  implement.
- **The one remaining timing-critical gap is SCAN_RSP.** Answering a `SCAN_REQ`
  within T_IFS needs the same hardware turnaround as the connection ACK, so it
  belongs down in `ble_radio.rs`, not in the portable layers. Without it the
  device is discoverable by BlueZ (lenient) but not reliably by nRF Connect on
  Android (which active-scans and wants a scan response).

---

## 5. The bug-fix journey (chronological)

This is the useful part for a new session: the failures we hit and why, so the
same ground isn't re-tilled. Commits are on the branch, newest last.

1. **`369d2a93` — kernel-mode advertising in the BLE capsule.** The first
   attempt was a standalone `BleTestAdvertiser` board capsule that called
   `radio.set_transmit_client(self)` / `set_receive_client(self)`, which
   *overwrote* the advertising driver's client registrations and made its
   AdvertisingRx state machine dead code — and it re-implemented `parse_connect_ind`
   / the ADV→RX cycle that already existed. Fix: add
   `start_connectable_advertising()` to the advertising capsule itself (kernel
   path through the *existing* state machine), delete the board capsule.

2. **`bff32e8e` — SCAN_REQ handling.** Device showed in `bluetoothctl` but not
   nRF Connect; with `ADV_NONCONN_IND` it showed in both. Android active-scans:
   after `ADV_IND` it sends `SCAN_REQ`. We were treating any non-CONNECT_IND as
   a cue to advance channel, so the device "vanished" the instant it got a
   `SCAN_REQ`. Fix: re-arm RX on the same channel; let the 3 ms alarm be the
   only thing that advances channels. (Real fix is still SCAN_RSP — see §7.)

3. **`e1bc11f1` — first connection-event timing (the big one).** CONNECT_IND was
   parsed fine but the central aborted (`le-connection-abort-by-local`). Cause:
   `schedule_next_event` unconditionally computed `open_time = last_anchor +
   interval - …`, which is right for events *after* the first but for the first
   event was missing the 1250 µs `transmitWindowDelay` **and** added a whole
   `connInterval` — so we opened the RX window ~one interval too late, every
   time. Fix: compute an absolute `next_open_time`; the first event uses
   `timer0_now + transmitWindowDelay + WinOffset` (window start), later events
   use `last_anchor + (missed+1)*interval - widening - guard`. Single source of
   truth read by both the coarse-alarm arming and the hardware RX-open compare.

4. **`b94a9553` — clean disconnect + resume advertising.** We only left a
   connection via supervision timeout, and then went dark. Fix: detect
   `LL_TERMINATE_IND` in `connection_event_done`; the advertising capsule
   implements `DisconnectClient` so `connection_lost()` restarts advertising
   (`ble_initialize` fully restores advertising-mode AA/CRC/SHORTS).

5. **`85c24992` — LL SN/NESN acknowledgement (the second big one).** The
   connection "held" but no LL procedure ever completed: a debug trace showed
   the master retransmitting an identical `LL_FEATURE_REQ` on *every* event
   (same SN). We always sent NESN/SN = 0, so the master never saw an ack. Fix:
   implement the 1-bit sequence-number scheme (Vol 6 Part B §4.5.9) **in the
   RX-phase DISABLED ISR** — the only place with correct timing, since the reply
   is hardware-triggered and must carry the ack for the packet just received.

6. **`4da990d9` / `59ed9201` — flow control + control-PDU responses.** Plumbed a
   `tx_acked` signal from the ISR up to the manager, then added a stop-and-wait
   TX state machine (`Idle → FreshContent → AwaitingAck`) and built real
   responses (`LL_FEATURE_RSP`, `LL_VERSION_IND`, `LL_UNKNOWN_RSP`). The ISR
   sends an **empty PDU on the ack event** (gated by a `tx_fresh` flag so a
   first transmission isn't suppressed) to avoid re-sending acked content with
   an advanced SN, which the master would see as a duplicate.

7. **`255bb0bc` — don't drop the control PDU in the become-idle event.** The
   master sent `VERSION_IND` in the same event it acked our `FEATURE_RSP`, and
   the `AwaitingAck → Idle` branch cleared state without inspecting the RX. Fix:
   after advancing flow-control state, if we are now free to load a payload,
   inspect the current event's RX for a response.

8. **`da508e62` — outbound response queue.** Still died at ~40 s: the ATT
   `EXCHANGE_MTU_REQ` arrived while we were mid-transmitting `VERSION_IND` and
   was dropped (ATT is a *separate layer*, so the master pipelines it right
   after the LL version exchange). Fix: build a response for every request as it
   arrives and **queue** it (small FIFO); the stop-and-wait TX drains one per
   acked event. Overlapping/pipelined requests are answered in order.

9. **`f673e67d` → `3361f643` — ATT / GATT.** First a minimal attribute-less ATT
   responder (MTU + error-to-everything) to complete transactions; then a real
   minimal GATT server (service `0xFFF0`, read/write characteristic `0xFFF1`).

10. **`43c60282` — ATT PDU bounds.** A 3-byte write read back as `01 02 03` +
    17 bytes of garbage: `build_att_response` sliced the ATT PDU as `rx[6..]`
    (to the end of the 64-byte buffer) instead of to the real PDU length, so the
    write value grabbed stale buffer bytes. Fix: bound the ATT PDU using the
    L2CAP length field, clamped to the LL length and the buffer.

Diagnostic commits along the way: `d88beda4` (log RX headers, dump on teardown),
`6fc2fca9` (control-PDU log), `5ef4edec` (log all non-empty PDUs incl. data).

---

## 6. Known outstanding tasks

### Timing-critical (belongs in `ble_radio.rs` / controller)
- [ ] **SCAN_RSP.** Answer `SCAN_REQ` within T_IFS via the hardware turnaround
      (reuse the connection-event SHORTS mechanism, gated so a `CONNECT_IND` in
      the same window is *not* answered with a scan response). Needed for nRF
      Connect / Android discoverability and spec conformance. This is the only
      remaining timing-sensitive item.

### Robustness (LL, portable-ish)
- [ ] **Apply `LL_CHANNEL_MAP_IND` and `LL_CONNECTION_UPDATE_IND`.** Currently
      acked at the LL level but *ignored*. Both carry an `Instant` (a
      connEventCount at which the change takes effect on both sides); correct
      handling must stash the new params and apply them exactly at the Instant
      (mind 16-bit wraparound vs. our event counter; CONNECTION_UPDATE must
      re-anchor/re-time the whole schedule). Left unimplemented because observed
      masters send `CHANNEL_MAP_IND` but don't appear to switch, so we cannot
      test it. **See the TODO comment at the handling site in
      `ble_ll_connection.rs` (`build_control_response`,
      `LL_CONNECTION_UPDATE_IND | LL_CHANNEL_MAP_IND` arm).**

### Architecture / design (the main next chunk — see §7 chip discussion)
- [ ] **Refactor the layering.** `ble_ll_connection.rs` currently spans LL →
      L2CAP → ATT → GATT in one capsule. Split into: a controller/LL layer
      (chip-adjacent, timing), a portable L2CAP demux (by CID), a portable ATT
      layer, and **GATT as a combination of a kernel capsule + userspace
      processes** — services/attributes registered by processes, with the capsule
      doing L2CAP/ATT and dispatching ATT operations to the process that owns a
      given handle range. Design the kernel/userspace boundary deliberately.
- [ ] **Evaluate the HIL against a second, meaningfully different chip** before
      committing to the design (see §7).

### Features (host, portable)
- [ ] **Notifications / indications** (device→host push): CCCD descriptor +
      Handle Value Notification. Natural next GATT feature.
- [ ] **Larger MTU + L2CAP/LL fragmentation** (only if values > ~20 bytes are
      needed).
- [ ] **L2CAP connection-oriented channels (CoC)** on CID `0x0005` signalling +
      dynamic CIDs, if raw-socket / non-GATT clients are a target.
- [ ] **Security Manager (SMP, CID `0x0006`)** if pairing/encryption is needed.

### Cleanup
- [ ] **Trim / gate the diagnostics.** The `DebugEntry` and `CtrlEntry` ring
      buffers and the teardown `debug!` dumps in `ble_ll_connection.rs` are
      scaffolding. Keep while iterating; gate or remove before merge.
- [ ] The GATT attribute table and characteristic value are **hardcoded** in the
      capsule — placeholder until the userspace GATT design lands.

---

## 7. Multi-chip / HIL evaluation

The current HIL (`BleAdvertisementDriver` + `BleConnectionDriver`) was written
against the nRF52 and is **raw-radio-shaped**: it exposes per-channel transmit,
`connection_event_start(channel, tx_buf, open_time_ticks)`, `get_timer0_now()`,
etc. The design should be validated against at least one chip that is
*meaningfully* different — not just another Nordic part.

Survey of the chips in this tree (`chips/*/src/*.rs`, looking for radio support):

| Chip | Radio situation | Suitability as a 2nd BLE target |
|------|-----------------|---------------------------------|
| `nrf52*` / `nrf5x` | Raw, CPU-programmable 2.4 GHz radio + PPI + TIMER. `ble_radio.rs`, `ieee802154_radio.rs`. | **Current impl.** (`wm1110dev` is also nRF52840 — same IP, does not count.) |
| **`apollo3`** (Ambiq Apollo3 Blue) | **HCI-style controller.** `chips/apollo3/src/ble.rs` already implements `BleAdvertisementDriver`, but via a FIFO/MSPI register block (`fifo`, `fifopush`, `mspicfg`, `blecfg`, `pwrcmd`) that shovels **HCI commands** to an internal BLE core. Note `transmit_advertisement(buf, len, _channel)` **ignores the channel** and `set_tx_power` is a no-op — the controller owns channel/timing. There is an `apollo3` board in-tree. | **Best "meaningfully different" target.** It will immediately expose that `BleConnectionDriver` (TIMER ticks, per-event channel, raw TX buffer) does **not** map to an HCI controller at all, and that even `BleAdvertisementDriver`'s per-channel model is raw-radio-specific. This is precisely the evaluation we want. |
| `stm32wle5xx` | `subghz_radio.rs` — a programmable radio, but **sub-GHz** (SX126x-class, LoRa/FSK), not 2.4 GHz. | Not BLE-capable (wrong band). Interesting only as another "raw programmable radio" data point for a generic radio HIL, not for BLE. |
| `esp32`, `esp32-c3` | 2.4 GHz WiFi+BLE, but BLE runs on an internal controller / ROM blob (ESP-IDF controller). Not openly, rawly programmable. | HCI/controller-mediated in practice; messy. Secondary to Apollo3. |
| `rp2040`/`rp2350` (`raspberry_pi_pico_w`) | BLE via external **CYW43439** combo chip over SPI (HCI-ish/blob). | Another HCI-over-transport candidate, external. |
| everything else (`sam4l`, `stm32f4*`, `msp432`, `litex`, riscv parts, …) | No BLE/2.4 GHz radio. | N/A |

**Recommendation / key insight for the design:** the nRF52 is *unusual* in
exposing the raw radio so the LL can run in software with hardware timing
assist. **Most integrated-BLE parts run the LL on a dedicated controller and
expose HCI.** So the second implementation should almost certainly be an
**HCI-based controller (Apollo3 is in-tree and the obvious choice)**, and the
real design question it forces is: *where is the controller/host boundary in the
HIL?*

- With a raw radio (nRF52) we implement the LL ourselves in Tock.
- With an HCI controller (Apollo3) the LL is *already implemented* in the
  controller; Tock should speak HCI and the whole `BleConnectionDriver`
  timing/channel abstraction is meaningless.

That strongly suggests the durable HIL boundary is **HCI-shaped** (or at least
that there are two tiers: a raw-radio "build-your-own-LL" tier and an
HCI "talk-to-a-controller" tier), with the portable L2CAP/ATT/GATT host stack
sitting on top of *either*. Validating this against Apollo3 before hardening the
HIL is the recommended next design step.

---

## 8. Spec references (Bluetooth Core Spec)

- Link Layer, connection state, timing: **Vol 6, Part B** (esp. §4.5 —
  connection setup/§4.5.3 transmit window, §4.5.8 CSA#1 channel selection,
  §4.5.9 SN/NESN acknowledgement).
- LL control PDUs / procedures: **Vol 6 Part B §2.4**, **Vol 6 Part B §5.1**.
- L2CAP: **Vol 3, Part A** (LE fixed channels, CoC).
- ATT: **Vol 3, Part F** (PDU formats, opcodes, error codes).
- GATT: **Vol 3, Part G** (service/characteristic/descriptor model,
  discovery procedures).

---

## 9. Breadth of SoC support — Zephyr parity & the HCI boundary

Research question: if we want to support BLE across many SoCs (medical,
automotive, wearables, home IoT), what's the cheapest path, and how far does an
**HCI-based interface** get us? Findings below are from Zephyr's structure +
vendor docs (verified via web search 2026-07; fine details worth re-checking).

### What Zephyr does (the reference)

- Zephyr runs its **own open-source Controller (link layer) on essentially only
  Nordic** (nRF51/52/53) plus one Nordic-derived "proprietary radio" (openisa
  RV32M1). That's the raw-radio tier — tiny.
- **Every other family is reached via an HCI driver** to a vendor/coprocessor
  controller. HCI is a Bluetooth-SIG standard (commands/events/ACL framing),
  identical across controllers. Zephyr's `drivers/bluetooth/hci/`:
  - Generic transports: `h4.c` (UART), H5 (3-wire), SPI, **IPC/RPMsg**
    (multi-core), `userchan` (Linux).
  - Vendor/coprocessor: STM32WB (`ipm_stm32wb.c`, shared-RAM IPM → M0 blob),
    STM32WBA, STM32WB0, ESP32 (`hci_esp32.c`, VHCI), Silabs EFR32
    (`hci_silabs_efr32.c`), NXP (`hci_nxp.c`), Infineon CYW208xx + PSoC6 BLESS,
    Realtek Ameba.

Per-chip interface confirmations:

- **NXP KW45** (automotive; BLE 6.0 + CAN FD/LIN): CM33 app core + a **dedicated
  CM3 "NBU" radio core** (own flash, upgradeable software radio) reached over
  HCI — category-3 coprocessor.
- **STM32WB:** HCI over IPCC/IPM to a Cortex-M0 running ST's coprocessor binary
  (flash "Full stack" or "HCI Layer").
- **ADI MAX3266x / MAX32655 (Cordio):** on-chip controller; the split point is
  **HCI over UART**; controller can be built standalone; even a dual-core
  (Arm+RISC-V) split-HCI mode exists.
- **Silabs EFR32:** can run its LL on-chip over RAIL, but Zephyr still reaches it
  via an **HCI driver**.
- **TI CC13xx/CC26xx:** proprietary **RF-core command mailbox**, *not* HCI —
  outside the HCI umbrella (Zephyr largely doesn't do BLE on them either).

### Interface taxonomy (the design lens)

1. **Raw radio + software LL** (own PHY timing): Nordic nRF5x. *Rare — the
   current Tock impl.*
2. **On-chip LL over a vendor radio HAL:** Silabs (RAIL), STM32WBA, ADI MAX32
   (Cordio), Dialog/Renesas DA14xxx. Usually still exposes an HCI seam.
3. **HCI to on-chip coprocessor** (IPC/shared-mem/mailbox): STM32WB, ESP32,
   nRF5340/nRF54H net core, NXP KW45.
4. **HCI to external chip** (UART/SPI): Infineon AIROC/CYW43, generic modules.

Categories 3 & 4 (and most of 2 via their HCI seam) dominate the non-Nordic
market. Nordic (cat 1) is the outlier.

### Verdict on "HCI ≈ 99% of the way to 99% parity"

Directionally correct, with the cost in a different place than "a SPI driver":

- **True at the protocol level:** HCI is standardized, so one portable HCI host
  covers *all* HCI controllers; the marginal per-SoC work collapses to transport
  + bring-up glue.
- **Correction 1 — the dominant cost is the one-time, shared HCI *host* stack**
  (full GAP central+peripheral, GATT client+server, SMP pairing/bonding, L2CAP
  incl. CoC, privacy/RPA). Paid once, amortized over every chip. Our current
  host is a sliver (peripheral-only, one GATT server, no SMP/CoC).
- **Correction 2 — "transport" is ~3 families,** only one of which is literally
  a SPI driver: UART (H4/H5) and SPI are cheap (Tock has these on many chips);
  **IPC/shared-mem** (STM32WB IPCC, nRF5340 RPMsg, ESP32 VHCI) is real inter-core
  plumbing, and several parts need **firmware provisioning** (flash/upload a
  vendor blob) — the lumpy per-vendor tax.
- **Correction 3 — a few families are outside pure HCI:** TI RF-core (bespoke
  shim), and the raw-radio tier (Nordic) which needs the full software LL (mostly
  already built here).

### Parity ladder (effort → what it unlocks)

| Effort | Unlocks |
|--------|---------|
| Portable **HCI host** (GAP/L2CAP/ATT/GATT/SMP) + **H4/UART** transport | Any external HCI module over UART; testable with a cheap dongle |
| + **SPI** transport | SPI-attached controllers (some Infineon/Realtek/modules) |
| + **IPC/shared-mem** transport (one RPMsg-ish pattern) | nRF5340 net core, STM32WB (IPM), ESP32 (VHCI) |
| + per-vendor **bring-up glue** (firmware load, vendor HCI extensions, power seq) | Turns "transport works" into "chip boots BLE" |
| + keep the **nRF raw-radio LL behind an HCI shim** | Parity on the raw-radio tier without special-casing the host |
| + (optional) **TI RF-core shim** | The non-HCI holdout |

### Recommendation

Make **HCI the durable host/controller boundary.** Build a portable HCI host
(non-timing-sensitive, off-chip — the "up the stack" direction) and treat the
existing nRF raw-radio LL as one Tock-resident controller behind an HCI shim.
This gets most of Zephyr's SoC *breadth* cheaply on the per-chip axis; budget the
*host stack* as the real work, and IPC transports + firmware provisioning as the
bumpy per-vendor bits. Validate against one HCI controller first (an external
UART dongle is the simplest; Apollo3 is in-tree).

Sources: Zephyr Bluetooth features & controller-arch docs; Zephyr
`drivers/bluetooth/hci/` (`h4.c`, `ipm_stm32wb.c`, `hci_stm32wba.c`,
`hci_esp32.c`, `hci_silabs_efr32.c`, `nxp,hci-ble`, `infineon,cyw208xx-hci`);
NXP KW45 product/blog pages; ADI Cordio BLE User Guide + Zephyr MAX32655 board.

---

## 10. Kernel & user-space architecture: virtualizing the subsystem

Tock differs from Zephyr: it must serve **multiple mutually-distrustful apps
concurrently over virtualized hardware**, not cooperating tasks. That makes a
naive "one app owns the radio" interface unsatisfying. Design framing below
(discussion, not yet committed — the Model A/B fork is an open decision).

### The two-layer split (don't conflate these)

BLE virtualization is **two problems at two layers**:
- **(a) radio / role multiplexing at the controller** — a *scheduling* problem.
- **(b) application multiplexing at GATT** — a *namespace + access-control*
  problem (this is what Beetle [MobiSys'16] solved for gateways).

Both sit **above the HCI-shaped controller boundary** from §9, which is what
keeps the whole thing portable.

### Advertising vs connected: one subsystem, not two interfaces

The radio is singular; concurrent roles (advertise / scan / connect) need **one
scheduler that owns the radio timeline**. Two interfaces both grabbing the radio
is the `BleTestAdvertiser` mistake at scale. HCI already models this exactly
(advertising sets + scan + N connections as concurrent controller activities) —
so the host-facing interface should be "**activities on a controller**," and on
a real controller the concurrency comes for free. Capability gradient the
interface must express (and degrade gracefully — BUSY / capability query):

- multiple **non-connectable advertisers** (beacons): cheap, time-sliced — Tock
  does this today;
- **advertising + one connection**: needs interleaving adv into the connection's
  gaps — moderate LL-scheduler work on our nRF radio; native on HCI controllers;
- **multiple connections**: heavy; real embedded controllers support a small N.

### OPEN DECISION — "virtual devices" (A) vs "one device, virtualized GATT" (B)

- **Model A (today):** each app = a distinct advertised device (own identity).
  Extends to connections only as *N independent connections/identities* —
  impractical (a phone sees N devices; controller holds N links).
- **Model B (Beetle-shaped):** one identity, one connection (or few), GATT table
  composed from apps. Practical; matches BLE idiom (a phone sees one device with
  many services).
- **Current lean:** keep **A for non-connectable/beacon** use (cheap, real
  isolation), **converge connectable/connected operation on B**. Connections
  force B. *This is the pivotal call and cascades into everything above it —
  needs a deliberate decision.*

### Virtualize at GATT, not L2CAP

Forced by the protocol: there is exactly **one ATT channel (fixed CID 0x0004)
per connection**, so you cannot give each app its own ATT channel — the sharing
point is the GATT handle space. Multiplexing therefore *must* be at GATT (route
by handle, fan out notifications, per-characteristic ownership/ACL). That is
Beetle's thesis, and here it's not a preference. (L2CAP **CoC** virtualization =
socket-per-app is clean and worth offering for the raw-stream minority, but GATT
is the 80% case.) Two GATT virtualizations, both at the GATT layer:
- **Peripheral (Tock exposes a server):** compose one GATT table from per-process
  attribute contributions; route incoming ATT ops to the owning process; each
  process owns its characteristics + notifications. **The immediate common case
  — start here.**
- **Central/gateway (Tock accesses remote peripherals):** Beetle's exact scenario
  — cross-device handle mapping, subscription fan-out, policy, caching. Later.

### Kernel or user space?

Put the **core GATT mux in a kernel capsule**; push rich policy to user space.
Rationale: Beetle was a user-space daemon because the *Linux* kernel is a
general-purpose OS with no business embedding BLE policy. **Tock inverts this —
capsules *are* the purpose-built trusted mediation layer**, and the ATT-channel
demux + GATT-table composition + op-routing is the standard Tock virtualizer
pattern (own a shared resource, route to processes via grants + upcalls, enforce
ownership at registration) — same shape as `VirtualMuxAlarm` / virtual UART. A
capsule avoids a mandatory universally-trusted broker process and the double
process-boundary crossing per ATT op. Keep the capsule minimal: ownership +
routing + notification fan-out, coarse/static policy. In the peripheral capsule
"access control" mostly reduces to **ownership** (a process owns its handle
range; only it gets that range's writes and may push its notifications);
cross-app access is where real *policy* enters — defer, or gate behind explicit
capabilities / board config. The richer Beetle features (dynamic policy,
central-mode cross-device brokering, GATT-over-network bridging) → a **user-space
service on top**, esp. for gateway deployments.

### Layering sketch

```
processes   ── register attributes; read/write/subscribe upcalls; push notifications
   │ (syscall)
GattServer mux capsule   ── compose table, assign handles, route by handle, per-proc CCCD/notify
L2capMux capsule         ── demux by CID → ATT / signalling(CoC) / SMP
LinkController (HCI-shaped) ── activities: adv sets, scan, connections; ACL data in/out
   └── vendor HCI controller  OR  our nRF raw-radio LL behind an HCI shim
```
Everything from `L2capMux` up is portable, write-once, rides any controller.

### Isochronous streams (LE Audio) — a MISSING, orthogonal data path

The sketch above covers only the **ACL → L2CAP → GATT** path. BLE 5.2 **LE Audio
/ Isochronous Channels (ISO)** are **not** carried over L2CAP and are currently
**scoped out**. This is not a flaw in the GATT design (ISO is orthogonal), but
the subsystem architecture must reserve a place for it:

- **Two flavours:** **CIS** (Connected Isochronous Stream, in a CIG —
  point-to-point, bidirectional: earbuds, hearing aids) and **BIS** (Broadcast
  Isochronous Stream, in a BIG — Auracast broadcast).
- **Separate controller data path.** ISO SDUs go through the **ISOAL**
  (Isochronous Adaptation Layer, seg/reassembly + timing) to ISO PDUs, carried as
  **HCI ISO data packets** — a *sibling* of the ACL data path, **bypassing
  L2CAP/ATT/GATT entirely**. It slots in cleanly next to `L2capMux` at the
  controller boundary; it does not disturb the GATT design.
- **Split plane:** LE Audio's **control plane** (BAP/ASCS/PACS/VCP/MCP/CSIP…) is
  **GATT-based** → reuses the portable GATT path. Only the **media plane** is ISO.
- **Harder real-time than connections.** ISO has presentation-time / bounded-
  latency semantics and is *lossy* (flush timeout, limited retransmission), not
  reliable like ATT. Scheduling CIS/BIS events alongside connection events on one
  radio is a serious real-time burden on a raw-radio LL → **strong extra argument
  for the HCI boundary** (lean on a LE-Audio-capable controller's ISO; building
  it on our own nRF52 LL would be a major effort, and **nRF52 largely lacks LE
  Audio — nRF5340 + a capable controller has it**; capability-gated, query it).
- **Different virtualization model.** A stream is real-time media with QoS, not an
  attribute — it does **not** fit GATT-style sharing. The natural model is
  **exclusive assignment of a CIS/BIS to one app** (multiple streams → multiple
  apps, but each stream owned), closer to the CoC "stream socket" model with
  isochronous QoS. The **LC3 codec** is a compute/media concern (app / user space
  / hardware codec), out of this layering.
- **Placement:** ISO data path + ISOAL is timing-sensitive → kernel capsule
  adjacent to `LinkController`; LE Audio profiles ride the portable GATT path;
  media source/sink + codec live above.

Bottom line: reserve **ISO as a peer of L2CAP at the controller boundary**, with
its own exclusive-stream virtualization; it reuses GATT for control but needs a
separate real-time media path and (realistically) an LE-Audio-capable controller.
