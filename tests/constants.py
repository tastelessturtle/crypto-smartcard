# applet id
AID: str = "5714e4720af2152cb449b1d8"

# constants
SW1_GOOD: int = 0x90
SW2_GOOD: int = 0x00

# instructions
INS_HELLO_WORLD: int = 0x40
INS_SELECT_APP: int = 0xA4
INS_ECDSA_SIGN: int = 0xEA
INS_ECDSA_VERIFY: int = 0xEB
INS_ECDSA_CONFIG: int = 0xEC
INS_ECDSA_GENKEY: int = 0xED
INS_ECDSA_SIGN_MESSAGE: int = 0xEE
P1_SELECT_AID: int = 0x04

# parameter constants
PAR_SECRET: int = 0x00
PAR_PUBLIC: int = 0x01
PAR_FIELD: int = 0x02
PAR_A: int = 0x03
PAR_B: int = 0x04
PAR_G: int = 0x05
PAR_R: int = 0x06
