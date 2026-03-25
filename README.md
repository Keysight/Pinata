# Pinata board

Pinata is a development board (ARM Cortex-M4F) that has been modified and programmed in order to be a training target 
for Side Channel Analysis (SCA) and Fault Injection (FI) attacks. It is based on the STM32F4Discovery board.

## Features

This section details the functions that Pinata is able to perform (additional details can be found
in the manual).

| Abbreviation | Meaning |
|--------------|---------|
| ENC          | Encrypt |
| DEC          | Decrypt |
| SIG          | Sign    |
| VER          | Verify  |

### Symmetric algorithms

#### DES

|       |                               | SW         | HW       |
|-------|-------------------------------|------------|----------|
| DES   |                               |            |          |
|       | Standard                      | ENC, DEC   | ENC, DEC |
|       | Countermeasures (selectable)  | ENC        | -        |
| 3DES2 |                               |            |          |
|       | Standard                      | ENC, DEC   | ENC, DEC |

#### AES

|         |                              | SW       | HW       |
|---------|------------------------------|----------|----------|
| AES-128 |                              |          |          |
|         | Standard                     | ENC, DEC | ENC, DEC |
|         | Countermeasures (selectable) | ENC, DEC | -        |
|         | T-tables                     | ENC, DEC | -        |
|         | Masked                       | ENC, DEC | -        |
| AES-256 |                              |          |          |
|         | Standard                     | ENC, DEC | ENC, DEC |

#### SM4
|     |          | SW       | HW |
|-----|----------|----------|----|
| SM4 |          |          |    |
|     | Textbook | ENC, DEC | -  |
|     | OpenSSL  | ENC, DEC | -  |

#### PRESENT
|         |          | SW       | HW |
|---------|----------|----------|----|
| PRESENT |          |          |    |
|         | Textbook | ENC, DEC | -  |

### Asymmetric algorithms 
#### RSA
|          |                            | SW  | HW |
|----------|----------------------------|-----|----|
| RSA-1024 |                            |     |    |
|          | CRT                        | DEC | -  |
| RSA-512  |                            |     |    |
|          | SFM: Full                  | DEC | -  |
|          | SFM: Exponentiation only   | DEC | -  |

#### ECC
|          |                       | SW | HW |
|----------|-----------------------|----|----|
| ECC25519 |                       |    | -  |
|          | Scalar multiplication | v  | -  |

#### SM2
|     |          | SW            | HW |
|-----|----------|---------------|----|
| SM2 |          |               | -  |
|     | Standard | ENC, DEC, SIG | -  |

#### Lattice-based
|                    |        | SW       | HW |
|--------------------|--------|----------|----|
| ML-DSA FIPS 204    |        |          | -  |
|                    |     44 | -        | -  |
|                    |     65 | SIG, VER | -  |
|                    |     87 | -        | -  |
| MKL-KEM FIPS 203   |        |          |    |
|                    |    512 | ENC, DEC | -  |
|                    |    768 | -        | -  |
|                    |   1024 | -        | -  |

Note: ML-DSA and ML-KEM are implemented in terms of the [PQM4 library for Cortex-M4 processors](https://github.com/mupq/pqm4.git). The exact git commit hash that is used can be found in the src/CMakeLists.txt file. The library is downloaded into the $BUILD/\_deps/pqm4-src folder.

### Hash functions

#### SHA
|      |          | SW | HW |
|------|----------|----|----|
| SHA1 |          |    |    |
|      | Standard | -  | v  |
Hardware only

#### HMAC
|      |          | SW  | HW |
|------|----------|-----|----|
| SHA1 |          |     |    |
|      | Standard | ENC | -  |

#### SM3
|     |          | SW | HW |
|-----|----------|----|----|
| SM3 |          |    |    |
|     | Standard | v  | -  |

## Building Pinata Firmware

You can build Pinata firmware either using WSL or on a native linux machine. The description below is based on an UBUNTU 22.04 machine. These steps will also work for WSL, but to get access to the Pinata board in WSL, see the troubleshooting steps about Windows and WSL.

### Requirements

For cross-compiling, and flashing, the STM32F4Discovery board, install the following packages:
```sh
sudo apt-get install gcc-arm-none-eabi cmake dfu-util
```

### Cross-compiling the firmware

#### Configure

Run the following command to configure the project for the gcc-arm-non-eabi compiler toolchain:

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=gcc-arm-none-eabi.toolchain.cmake -S . -B build
```

This will create a ./build folder where you run your Makefile targets. You may customize the path to your compiler toolchain by definining a `PREFIX` variable on the command-line when invoking cmake. See the `gcc-arm-none-eabi.toolchain.cmake` toolchain file for details. (For regular Ubuntu/WSL installations, you don't need to modify the `PREFIX` variable).

#### Build

To build everything, just run `make` inside the configured ./build folder.

This will compile all Pinata variations, which are currently "classic", "hw", and "pqc". Output binaries can be found in the `./build/src` folder.

* The "classic" variant contains non-pqc software ciphers.
* The "hw" variant contains non-pqc software ciphers, as well as _hardware-accelerated_ ciphers.
* The "pqc" variant contains ML-DSA FIPS 204 and ML-KEM FIPS 203 software implementations.

Example of compiling a particular firmware:

In general, there is a `help` Makefile target defined that you may invoke to view the possible targets to build.

### Flashing the firmware (Linux-based)

Add a udev rule for the Pinata:

```sh
sudo mkdir -p /etc/udev/rules.d && echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", MODE="0666", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/69-pinata.rules
```

Add your user to the `plugdev` group:

```sh
sudo usermod -a -G plugdev $USER
```

Check if the physical Pinata is connected to the build machine using the micro USB port on the Pinata.

Each firmware variant (classic, hw, pqc) has an associated "flash target" that allows one to flash the device while making sure the firmware is up-to-date with the source code. These special targets are named:

* classic_flash
* hw_flash
* pqc_flash

For example, run the following command for flashing the classic firmware onto the connected device:

```sh
make classic_flash
```

This is assuming you configured with the _Unix Makefiles_ generator.

## Testing

We maintain some integration tests for ensuring the ciphers on the device match reference implementations in the real world. For more information on testing Pinata functionality, see [PinataTests/README.md](PinataTests/README.md).

## Usage

The Pinata firmware works in a "request-response" manner where it waits for a command to appear via UART, optionally with arguments, then processes the command, and then optionally sends back a response.

The available commands are described in the src/main.h file. In there, each `#define` line that starts with `CMD_` is a possible request. Each command is 1 byte, and the argument list for the command depends on the particular command. The arguments for the command are described in comments above the `#define` line.

For the purposes of side-channel analysis, you are supposed to measure the voltage of the chip while the Pinata firmware is running a cryptographic operation. This has been made easy for you to do, because the interesting operations are wrapped in macro blocks named `BEGIN_INTERESTING_STUFF` and `END_INTERESTING_STUFF`. These macros will set GPIO Pin 2 to high and low, respectively. This allows you to trigger an oscilloscope on this GPIO pin and you'll know exactly where the interesting operation happens.

## Troubleshooting

### List USB devices:

```sh
lsusb
```

Example output:

```
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 002 Device 003: ID 0483:df11 STMicroelectronics STM Device in DFU Mode
Bus 002 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub
```

### List DFU-mode USB devices:

```sh
dfu-util --list
```

Example output:

```
Found DFU: [0483:df11] ver=2200, devnum=3, cfg=1, intf=0, path="2-2", alt=3, name="@Device Feature/0xFFFF0000/01*004 e", serial="208338865643"
Found DFU: [0483:df11] ver=2200, devnum=3, cfg=1, intf=0, path="2-2", alt=2, name="@OTP Memory /0x1FFF7800/01*512 e,01*016 e", serial="208338865643"
Found DFU: [0483:df11] ver=2200, devnum=3, cfg=1, intf=0, path="2-2", alt=1, name="@Option Bytes  /0x1FFFC000/01*016 e", serial="208338865643"
Found DFU: [0483:df11] ver=2200, devnum=3, cfg=1, intf=0, path="2-2", alt=0, name="@Internal Flash  /0x08000000/04*016Kg,01*064Kg,07*128Kg", serial="208338865643"
```

### Backup old firmware on device

In case you want to do a back up of Pinata firmware before you flash it:
```sh
dfu-util -a 0 -s 0x08000000:97812 -U backup.bin
```

### What TTY file should I use?

Use the symbolic links in `/dev/serial/by-id`.

### What serial port settings should I use?

Baud rate: 115200
Word length: 8 bits
Stop bits: 1
Parity: no
Flow control: disabled

### Permission denied for /dev/ttyUSB0

You need to be part of the `dialout` group to be able to open serial ports. Run

```sh
sudo usermod -a -G dialout $USER
```

### Pinata board not recognized by Windows

If you are planning to program the Pinata using wsl or from a virtual machine in Windows, the operating system must 
first be able to recognize the Pinata hardware device. For that, you must install the USB driver for the device, which
can be found here: https://www.st.com/en/development-tools/stsw-link009.html.


### USB ports not present in wsl

In order for wsl to have access to the pinata board, the USB port on which the board is connect needs to be connected 
to wsl. This can be done by following the following guide: https://learn.microsoft.com/en-us/windows/wsl/connect-usb.
