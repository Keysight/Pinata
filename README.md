# Pinata board

Pinata is a development board (ARM Cortex-M4F) that has been modified and programmed in order to be a training target 
for Side Channel Analysis (SCA) and Fault Injection (FI) attacks.

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
| CRYSTALS-Dilithium |        |          | -  |
|                    | LEVEL2 | -        | -  |
|                    | LEVEL3 | SIG, VER | -  |
|                    | LEVEL5 | -        | -  |
| CRYSTALS-Kyber     |        |          |    |
|                    |    512 | ENC, DEC | -  |
|                    |    768 | -        | -  |
|                    |   1024 | -        | -  |
|                    | 512-90s| -        | -  |
|                    | 768-90s| -        | -  |
|                    |1024-90s| -        | -  |


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

You can build pinata firmware either using wsl or on a native linux machine. The description bellow is based on UBUNTU 22.04 machine

### Requirements

For cross - compiling the STM32F4Discovery board, you will need a `gcc-arm-none-eabi` toolchain and `cmake`
```sh
sudo apt-get install gcc-arm-none-eabi cmake
```

For flashing the STM32F4Discovery board, you will need the dfu-util toolkit:
```sh
sudo apt-get install dfu-util
```

### Cross-compiling the firmware

For cross-compiling pinata:

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=gcc-arm-none-eabi.toolchain.cmake -S. -Bbuild && cmake --build build
```

This will compile all Pinata variations. Output binaries can be found in the `build` folder.

Example of compiling a particular firmware:

```sh
 cmake --build build --target classic_bin
```

### Flashing the firmware

Add a udev rule for the Pinata:

```sh
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", MODE="0666", GROUP="plugdev"' > /etc/udev/rules.d/69-pinata.rules
```

Add user to the `plugdev` group:

```sh
sudo usermod -a -G plugdev $USER
```

Check if the physical Pinata is connected to the build machine using the micro USB port on the Pinata.

Run the following command for flashing classic firmware

```sh
cmake --build build --target classic_flash
```

Note that this command also makes sure the firmware binary is up-to-date, so for quick iteration loops you can just always run this after editing source code.

## Testing

For more information on testing Pinata functionality, see [PinataTests/README.md](PinataTests/README.md).

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
