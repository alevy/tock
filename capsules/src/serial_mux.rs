use kernel::hil::uart;
use kernel::common::cells::TakeCell;

pub struct SerialMux<'a> {
    uart: &'a uart::UartData<'a>,
    header_buf: TakeCell<'static, [u8]>,
}

impl<'a> SerialMux<'a> {
    pub fn transmit(&self, address: u8, buffer: Buffer) {
        self.header_buf.take().map(|header_buf| {
            header_buf[0] = buffer.len() as u8;
            header_buf[1] = address;
            self.uart.transmit_buffer(header_buf , 2);
        });
    }
}

impl<'a> uart::TransmitClient for SerialMux<'a> {

}

pub struct Serial<'a> {
    mux: &'a SerialMux<'a>,
    address: u8,
}

pub type Buffer = &'static [u8];

impl<'a> Serial<'a> {
    pub fn transmit(&self, buffer: Buffer) {
        self.mux.transmit(self.address, buffer);
    }
}
