# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Tock Contributors 2022.

# Makefile for building the tock kernel for the HiFive1 platform

include ../Makefile.common

TOCKLOADER=tockloader
KERNEL_ADDRESS=0x400000

TOCKLOADER_OPENOCD_FLAGS = --openocd --board arty

# Default target for installing the kernel.
.PHONY: install
install: flash

.PHONY: flash-tockloader
flash-tockloader: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	$(TOCKLOADER) $(TOCKLOADER_GENERAL_FLAGS) flash --address $(KERNEL_ADDRESS) $(TOCKLOADER_OPENOCD_FLAGS) $<

flash: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	openocd -f openocd/arty-openocd-digilent.cfg \
		-c "init; jtagspi_init 0 openocd/bscan_spi_xc7a100t.bit; jtagspi_program $< 0x400000; shutdown"

flash-e21: core/sifive_coreip_E21_AHB_rtl_eval_v19_05p1_release_arty_a7_100t.mcs
	openocd -f openocd/arty-openocd-digilent.cfg \
		-c "init; jtagspi_init 0 openocd/bscan_spi_xc7a100t.bit; jtagspi_program $< 0x0; shutdown"

