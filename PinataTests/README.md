# Testing the Pinata

This project is for testing ciphers on Pinata.

## Step 1

Run

```sh
git submodule update --init --recursive
```

To initialize and fetch PQClean repo

## Step 2

For Debian/Ubuntu, install the following system packages:

```sh
apt install libboost-dev libssl-dev libgtest-dev
```

It's possible you may be able to use a different clang version. In that case, you will have to modify the `Makefile` to modify the clang version to your specific version.

To be able to run and debug tests in VSCode (or any other text editor with LSP capabilities), install the following packages:


```sh
apt install clangd
```

## Step 3

Compile the tests

```sh
cmake -S. -Bbuild -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cd build && make
```

Enabling the option `CMAKE_EXPORT_COMPILE_COMMANDS` is optional. It creates the JSON compilation database (a file named `compile_commands.json`), which clangd will use for code autocompletion, navigation and suggestions.

## Step 4

Let the Test Application know what serial port to use. Set and export an environment variable called `SERIAL_PORT` in your shell. For example, at the time of writing this was my serial port used for my physical Pinata:

```sh
export SERIAL_PORT=/dev/serial/by-id/usb-FTDI_TTL232R-3V3_FT9S6WRO-if00-port0
```

## Step 5

Run the tests

```sh
./build/PinataTests
```

To see the list of all test cases:

```sh
./build/PinataTests --gtest_list_tests
```

To run a specific test case of the test suite:

 ```sh
./build/PinataTests --gtest_filter=test128AESSWEncrypt
```
 
Note that wildcards work for filtering test cases. For example, `/build/PinataTests --gtest_filter=test128AES* ` will run all 128AES tests.

Run `./build/PinataTests --help` for help.
 