#
# This file is part of the MicroPython project, http://micropython.org/
#
# The MIT License (MIT)
#
# Copyright (c) 2019 Dan Halbert for Adafruit Industries
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Boards default to all modules enabled (with exceptions)
# Manually disable by overriding in #mpconfigboard.mk

# Smaller builds can be forced for resource constrained chips (typically SAMD21s
# without external flash) by setting CIRCUITPY_FULL_BUILD=0. Avoid using this 
# for merely incomplete ports, as it changes settings in other files.
ifndef CIRCUITPY_FULL_BUILD
    CIRCUITPY_FULL_BUILD = 1
endif
CFLAGS += -DCIRCUITPY_FULL_BUILD=$(CIRCUITPY_FULL_BUILD)


ifndef CIRCUITPY_AES
CIRCUITPY_AES = 0
endif
CFLAGS += -DCIRCUITPY_AES=$(CIRCUITPY_AES)

ifndef CIRCUITPY_ANALOGIO
CIRCUITPY_ANALOGIO = 1
endif
CFLAGS += -DCIRCUITPY_ANALOGIO=$(CIRCUITPY_ANALOGIO)

ifndef CIRCUITPY_AUDIOBUSIO
CIRCUITPY_AUDIOBUSIO = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_AUDIOBUSIO=$(CIRCUITPY_AUDIOBUSIO)

ifndef CIRCUITPY_AUDIOIO
CIRCUITPY_AUDIOIO = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_AUDIOIO=$(CIRCUITPY_AUDIOIO)

ifndef CIRCUITPY_AUDIOIO_COMPAT
CIRCUITPY_AUDIOIO_COMPAT = $(CIRCUITPY_AUDIOIO)
endif
CFLAGS += -DCIRCUITPY_AUDIOIO_COMPAT=$(CIRCUITPY_AUDIOIO_COMPAT)

ifndef CIRCUITPY_AUDIOPWMIO
CIRCUITPY_AUDIOPWMIO = 0
endif
CFLAGS += -DCIRCUITPY_AUDIOPWMIO=$(CIRCUITPY_AUDIOPWMIO)

ifndef CIRCUITPY_AUDIOCORE
ifeq ($(CIRCUITPY_AUDIOPWMIO),1)
CIRCUITPY_AUDIOCORE = $(CIRCUITPY_AUDIOPWMIO)
else
CIRCUITPY_AUDIOCORE = $(CIRCUITPY_AUDIOIO)
endif
endif
CFLAGS += -DCIRCUITPY_AUDIOCORE=$(CIRCUITPY_AUDIOCORE)

ifndef CIRCUITPY_AUDIOMIXER
CIRCUITPY_AUDIOMIXER = $(CIRCUITPY_AUDIOIO)
endif
CFLAGS += -DCIRCUITPY_AUDIOMIXER=$(CIRCUITPY_AUDIOMIXER)

ifndef CIRCUITPY_AUDIOMP3
ifeq ($(CIRCUITPY_FULL_BUILD),1)
CIRCUITPY_AUDIOMP3 = $(CIRCUITPY_AUDIOCORE)
else
CIRCUITPY_AUDIOMP3 = 0
endif
endif
CFLAGS += -DCIRCUITPY_AUDIOMP3=$(CIRCUITPY_AUDIOMP3)

ifndef CIRCUITPY_BITBANGIO
CIRCUITPY_BITBANGIO = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_BITBANGIO=$(CIRCUITPY_BITBANGIO)

# Explicitly enabled for boards that support _bleio.
ifndef CIRCUITPY_BLEIO
CIRCUITPY_BLEIO = 0
endif
CFLAGS += -DCIRCUITPY_BLEIO=$(CIRCUITPY_BLEIO)

ifndef CIRCUITPY_BOARD
CIRCUITPY_BOARD = 1
endif
CFLAGS += -DCIRCUITPY_BOARD=$(CIRCUITPY_BOARD)

ifndef CIRCUITPY_BUSIO
CIRCUITPY_BUSIO = 1
endif
CFLAGS += -DCIRCUITPY_BUSIO=$(CIRCUITPY_BUSIO)

ifndef CIRCUITPY_DIGITALIO
CIRCUITPY_DIGITALIO = 1
endif
CFLAGS += -DCIRCUITPY_DIGITALIO=$(CIRCUITPY_DIGITALIO)

ifndef CIRCUITPY_DISPLAYIO
CIRCUITPY_DISPLAYIO = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_DISPLAYIO=$(CIRCUITPY_DISPLAYIO)

ifndef CIRCUITPY_FRAMEBUFFERIO
CIRCUITPY_FRAMEBUFFERIO = 0
endif
CFLAGS += -DCIRCUITPY_FRAMEBUFFERIO=$(CIRCUITPY_FRAMEBUFFERIO)

ifndef CIRCUITPY_FREQUENCYIO
CIRCUITPY_FREQUENCYIO = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_FREQUENCYIO=$(CIRCUITPY_FREQUENCYIO)

ifndef CIRCUITPY_GAMEPAD
CIRCUITPY_GAMEPAD = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_GAMEPAD=$(CIRCUITPY_GAMEPAD)

ifndef CIRCUITPY_GAMEPADSHIFT
CIRCUITPY_GAMEPADSHIFT = 0
endif
CFLAGS += -DCIRCUITPY_GAMEPADSHIFT=$(CIRCUITPY_GAMEPADSHIFT)

ifndef CIRCUITPY_I2CSLAVE
CIRCUITPY_I2CSLAVE = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_I2CSLAVE=$(CIRCUITPY_I2CSLAVE)

ifndef CIRCUITPY_MATH
CIRCUITPY_MATH = 1
endif
CFLAGS += -DCIRCUITPY_MATH=$(CIRCUITPY_MATH)

ifndef CIRCUITPY__EVE
CIRCUITPY__EVE = 0
endif
CFLAGS += -DCIRCUITPY__EVE=$(CIRCUITPY__EVE)

ifndef CIRCUITPY_MICROCONTROLLER
CIRCUITPY_MICROCONTROLLER = 1
endif
CFLAGS += -DCIRCUITPY_MICROCONTROLLER=$(CIRCUITPY_MICROCONTROLLER)

ifndef CIRCUITPY_NEOPIXEL_WRITE
CIRCUITPY_NEOPIXEL_WRITE = 1
endif
CFLAGS += -DCIRCUITPY_NEOPIXEL_WRITE=$(CIRCUITPY_NEOPIXEL_WRITE)

# Enabled on SAMD51. Won't fit on SAMD21 builds. Not tested on nRF or STM32F4 builds.
ifndef CIRCUITPY_NETWORK
CIRCUITPY_NETWORK = 0
endif
CFLAGS += -DCIRCUITPY_NETWORK=$(CIRCUITPY_NETWORK)

ifndef CIRCUITPY_NVM
CIRCUITPY_NVM = 1
endif
CFLAGS += -DCIRCUITPY_NVM=$(CIRCUITPY_NVM)

ifndef CIRCUITPY_OS
CIRCUITPY_OS = 1
endif
CFLAGS += -DCIRCUITPY_OS=$(CIRCUITPY_OS)

ifndef CIRCUITPY_PIXELBUF
CIRCUITPY_PIXELBUF = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_PIXELBUF=$(CIRCUITPY_PIXELBUF)

# Only for SAMD boards for the moment
ifndef CIRCUITPY_RGBMATRIX
CIRCUITPY_RGBMATRIX = 0
endif
CFLAGS += -DCIRCUITPY_RGBMATRIX=$(CIRCUITPY_RGBMATRIX)

ifndef CIRCUITPY_PULSEIO
CIRCUITPY_PULSEIO = 1
endif
CFLAGS += -DCIRCUITPY_PULSEIO=$(CIRCUITPY_PULSEIO)

# Only for SAMD boards for the moment
ifndef CIRCUITPY_PS2IO
CIRCUITPY_PS2IO = 0
endif
CFLAGS += -DCIRCUITPY_PS2IO=$(CIRCUITPY_PS2IO)

ifndef CIRCUITPY_RANDOM
CIRCUITPY_RANDOM = 1
endif
CFLAGS += -DCIRCUITPY_RANDOM=$(CIRCUITPY_RANDOM)

ifndef CIRCUITPY_ROTARYIO
CIRCUITPY_ROTARYIO = 1
endif
CFLAGS += -DCIRCUITPY_ROTARYIO=$(CIRCUITPY_ROTARYIO)

ifndef CIRCUITPY_RTC
CIRCUITPY_RTC = 1
endif
CFLAGS += -DCIRCUITPY_RTC=$(CIRCUITPY_RTC)

# CIRCUITPY_SAMD is handled in the atmel-samd tree.
# Only for SAMD chips.
# Assume not a SAMD build.
ifndef CIRCUITPY_SAMD
CIRCUITPY_SAMD = 0
endif
CFLAGS += -DCIRCUITPY_SAMD=$(CIRCUITPY_SAMD)

# Currently always off.
ifndef CIRCUITPY_STAGE
CIRCUITPY_STAGE = 0
endif
CFLAGS += -DCIRCUITPY_STAGE=$(CIRCUITPY_STAGE)

ifndef CIRCUITPY_STORAGE
CIRCUITPY_STORAGE = 1
endif
CFLAGS += -DCIRCUITPY_STORAGE=$(CIRCUITPY_STORAGE)

ifndef CIRCUITPY_STRUCT
CIRCUITPY_STRUCT = 1
endif
CFLAGS += -DCIRCUITPY_STRUCT=$(CIRCUITPY_STRUCT)

ifndef CIRCUITPY_SUPERVISOR
CIRCUITPY_SUPERVISOR = 1
endif
CFLAGS += -DCIRCUITPY_SUPERVISOR=$(CIRCUITPY_SUPERVISOR)

ifndef CIRCUITPY_TIME
CIRCUITPY_TIME = 1
endif
CFLAGS += -DCIRCUITPY_TIME=$(CIRCUITPY_TIME)

# touchio might be native or generic. See circuitpy_defns.mk.
ifndef CIRCUITPY_TOUCHIO_USE_NATIVE
CIRCUITPY_TOUCHIO_USE_NATIVE = 0
endif
CFLAGS += -DCIRCUITPY_TOUCHIO_USE_NATIVE=$(CIRCUITPY_TOUCHIO_USE_NATIVE)

ifndef CIRCUITPY_TOUCHIO
CIRCUITPY_TOUCHIO = 1
endif
CFLAGS += -DCIRCUITPY_TOUCHIO=$(CIRCUITPY_TOUCHIO)

# For debugging.
ifndef CIRCUITPY_UHEAP
CIRCUITPY_UHEAP = 0
endif
CFLAGS += -DCIRCUITPY_UHEAP=$(CIRCUITPY_UHEAP)

ifndef CIRCUITPY_USB_HID
CIRCUITPY_USB_HID = 1
endif
CFLAGS += -DCIRCUITPY_USB_HID=$(CIRCUITPY_USB_HID)

ifndef CIRCUITPY_USB_MIDI
CIRCUITPY_USB_MIDI = 1
endif
CFLAGS += -DCIRCUITPY_USB_MIDI=$(CIRCUITPY_USB_MIDI)

ifndef CIRCUITPY_PEW
CIRCUITPY_PEW = 0
endif
CFLAGS += -DCIRCUITPY_PEW=$(CIRCUITPY_PEW)

# For debugging.
ifndef CIRCUITPY_USTACK
CIRCUITPY_USTACK = 0
endif
CFLAGS += -DCIRCUITPY_USTACK=$(CIRCUITPY_USTACK)

# Non-module conditionals

ifndef CIRCUITPY_BITBANG_APA102
CIRCUITPY_BITBANG_APA102 = 0
endif
CFLAGS += -DCIRCUITPY_BITBANG_APA102=$(CIRCUITPY_BITBANG_APA102)

# Should busio.I2C() check for pullups?
# Some boards in combination with certain peripherals may not want this.
ifndef CIRCUITPY_REQUIRE_I2C_PULLUPS
CIRCUITPY_REQUIRE_I2C_PULLUPS = 1
endif
CFLAGS += -DCIRCUITPY_REQUIRE_I2C_PULLUPS=$(CIRCUITPY_REQUIRE_I2C_PULLUPS)

# REPL over BLE
ifndef CIRCUITPY_SERIAL_BLE
CIRCUITPY_SERIAL_BLE = 0
endif
CFLAGS += -DCIRCUITPY_SERIAL_BLE=$(CIRCUITPY_SERIAL_BLE)

ifndef CIRCUITPY_BLE_FILE_SERVICE
CIRCUITPY_BLE_FILE_SERVICE = 0
endif
CFLAGS += -DCIRCUITPY_BLE_FILE_SERVICE=$(CIRCUITPY_BLE_FILE_SERVICE)

# REPL over UART
ifndef CIRCUITPY_SERIAL_UART
CIRCUITPY_SERIAL_UART = 0
endif
CFLAGS += -DCIRCUITPY_SERIAL_UART=$(CIRCUITPY_SERIAL_UART)

# ulab numerics library
ifndef CIRCUITPY_ULAB
CIRCUITPY_ULAB = $(CIRCUITPY_FULL_BUILD)
endif
CFLAGS += -DCIRCUITPY_ULAB=$(CIRCUITPY_ULAB)

# Enabled micropython.native decorator (experimental)
ifndef CIRCUITPY_ENABLE_MPY_NATIVE
CIRCUITPY_ENABLE_MPY_NATIVE = 0
endif
CFLAGS += -DCIRCUITPY_ENABLE_MPY_NATIVE=$(CIRCUITPY_ENABLE_MPY_NATIVE)
