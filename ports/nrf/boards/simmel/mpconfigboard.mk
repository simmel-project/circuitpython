USB_VID = 0x1209
USB_PID = 0xc051
USB_PRODUCT = "Simmel"
USB_MANUFACTURER = "Betrusted"

MCU_CHIP = nrf52833

# SPI_FLASH_FILESYSTEM = 1
# EXTERNAL_FLASH_DEVICE_COUNT = 1
# EXTERNAL_FLASH_DEVICES = "MX25R1635F"

INTERNAL_FLASH_FILESYSTEM = 1

CIRCUITPY_AESIO = 1
CIRCUITPY_AUDIOMP3 = 0
CIRCUITPY_BUSIO = 1
CIRCUITPY_DISPLAYIO = 0
CIRCUITPY_FRAMEBUFFERIO = 0
CIRCUITPY_NEOPIXEL_WRITE = 0
CIRCUITPY_NVM = 0
CIRCUITPY_PIXELBUF  = 0
CIRCUITPY_RGBMATRIX = 0
CIRCUITPY_ROTARYIO = 0
CIRCUITPY_RTC = 1
CIRCUITPY_TOUCHIO = 0
CIRCUITPY_ULAB = 0

# Enable micropython.native
#CIRCUITPY_ENABLE_MPY_NATIVE = 1

# These defines must be overridden before mpconfigboard.h is included, which is
# why they are passed on the command line.
CFLAGS += -DSPIM3_BUFFER_SIZE=0 -DSOFTDEVICE_RAM_SIZE='(32*1024)' -DNRFX_SPIM3_ENABLED=0
