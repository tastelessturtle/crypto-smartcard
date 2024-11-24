# Crypto Smartcard

## About the project

This project provides a testable applet for evaluating cryptographic functions on smartcards. Many modern smartcards come with integrated and secure cryptographic implementations, but using and testing these features can be complex. This applet simplifies the process, allowing security researchers, developers, and evaluators to easily test a wide range of cryptographic operations (e.g., encryption, decryption, hashing, digital signatures) directly on smartcard devices.

The applet will support common cryptographic algorithms, such as RSA, ECC, AES, SHA, ECDSA, and is designed to work with various smartcard models and standards (e.g., Java Card, GlobalPlatform). It includes pre-configured test cases to ensure correct and secure cryptographic operations. Additionally, the applet provides full control over the keys and parameters of the cryptographic functions, allowing for customizable testing scenarios.

Currently implemented features:

- ECDSA signing and verifying

This applet makes it easier to leverage the secure cryptographic implementations already integrated into many smartcards, providing a simple yet powerful tool for evaluating and validating their cryptographic capabilities in security research or development.

## Prerequisites

The following packages are required to run the project
  
- Python 3.10.0 or higher, with python packages `swig`, `pyscard`, `ecdsa`, `asn1` and `pytest`
- Java SDK version 11
- make
- smartcard reader drivers
- Ant

Most of these packages can be easily installed on Ubuntu: 

```shell
sudo apt update
sudo apt upgrade
sudo apt install make libpcsclite-dev pcscd openjdk-11-jdk ant

pip install swig pyscard ecdsa asn1 pytest
```

In addition to these packages, the following external tools are required:

- [JavaCard Ant](https://github.com/martinpaljak/ant-javacard)
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
- [JavaCard SDK](https://github.com/martinpaljak/oracle_javacard_sdks)

The JavaCard Ant and GPPro jar have been included in the `tools` folder, but I recommend to use the latest release versions. The JavaCard SDKs can be found in the github module folder in `libs` directory. Simply use `git pull` in the directory to pull all SDK versions.

## Using the repository
The repository is created and tested through the `Makefile`. Make has three commands:
- `make`: Removes the applet from the smartcard if it was present, builds the new applet, uploads the applet onto the smartcard and runs `pytest`.
- `make test`: Only runs `pytest`.
- `make clean`: Removes the applet from the smartcard if present and removes the temporary files in the repository


## Communication
Currently the smartcard has 1 cryptographic function installed and communicates through the APDU protocol. First select the applet with AID `57 14 e4 72 0a f2 15 2c b4 49 b1 d8`. Then, the following commands are available:

### Hellow World! (INS=0x40)
The hellow World! function returns `b'Hello World!'` to the host. The following command structure is used:

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0x40`|`0xNA`|`0xNA`|`0x00`|empty|Not checked|


### ECDSA Sign Hash (INS=0xEA)

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0xEA`|`0xNA`|`0xNA`|`0x20`|list of length 32 containing the 32 byte hash of SHA256|Not checked|


### ECDSA Verify (INS=0xEB)

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0xEB`|len(`message`)|len(`signature`)|`P1+P2`|list containing the message and signature pair|Not checked|


### ECDSA Get Configuration (INS=0xEC)

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0xEC`|See list below|`0xNA`|`0x00`|empty|Not checked|

`P1`: Depending on the parameter to be returned:
- `0x00`: Private Key
- `0x00`: Public Key
- `0x00`: Field
- `0x00`: Coefficient A
- `0x00`: Coefficient B
- `0x00`: G
- `0x00`: Order


### ECDSA Generate New Key (INS=0xED)
The applet comes with a default key loaded onto the ECDSA signature with NIST P256 curve parameters, The following keys are loaded:

Private Key: `0x65427b12cf91f31e4ff7555168f70ffe07bd723f94677a2a526b9fedb6bc13a6`


Public Key: `0x729f6f01072e3418bed3ccdf1db0ed8b76ad38b29acece53928de4f3f8ec7600c39ae0f5716c299cfe21b238af65e901f73a3dd1a0a66e2f1799ae0ebc22a62b`

To generate a new keypair use:

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0xED`|`0xNA`|`0xNA`|`0x00`|empty|Not checked|

### ECDSA Sign Message (INS=0xEE)

|CLA|INS|P1|P2|LC|DATA|LE|
|---|---|---|---|---|---|---|
|`0x00`|`0xEE`|`0xNA`|`0xNA`|len(`message`)|the message with given length|Not checked|\

The maximum message length is 128 bytes, but we advice the message to be at max `128-74=54` bytes. If the message is longer than 54 bytes, the used will not be able to verify the signature with the smartcard since the data for verification will exceed the maximum size of 128 bytes.


## License
The license falls under the MIT License and can be found in [`LICENSE.md`](./LICENSE.md).

## Roadmap
The following features and cryptographic algorithms are expected to be implemented:

- [x] ECDSA
- [ ] AES
- [ ] DES
- [ ] DSA
- [ ] Diffie-Helman
- [ ] HMAC
- [ ] RSA
- [ ] Checksums (CRC)
- [ ] Hashing (MD5, SHAx)
- [ ] Encryption modes such as CBC
- [ ] PIN functionality
- [ ] OneShot ciphers
