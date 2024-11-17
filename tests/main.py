# built-in modules
from random import randint
from hashlib import sha256
from _hashlib import HASH

# installed modules
from smartcard.System import readers
from smartcard.CardConnectionDecorator import CardConnectionDecorator

# ecdsa module
from ecdsa.curves import NIST256p
from ecdsa.ecdsa import Public_key, Private_key, Signature
from ecdsa.ellipticcurve import PointJacobi

# custom modules
from utils import list2bytes, str2list, list2str, int2str, list2int, bytes2list, encode_asn1, decode_asn1

# constants
AID: list = str2list("5714e4720af2152cb449b1d8")  # AID of the applet

# APDU response variables
data: list = []
sw1: int = 0
sw2: int = 0

# signature variables
r: int = 0
s: int = 0


def transmit(conn: CardConnectionDecorator, INS: int, P12: list = [0, 0], DATA: list = []) -> tuple[list, int, int]:
    """Transmits an APDU packet to the smartcard given a connection.

    Args:
        conn (CardConnectionDecorator): The connection object to the smartcard.
        INS (int): The APDU instruction byte (in integer form).
        P12 (list, optional): The APDUparameters. Defaults to [0, 0].
        DATA (list, optional): The APDU data. Defaults to [].

    Returns:
        tuple[list, int, int]: APDU response tuple (data, sw1, sw2)
    """
    # construct LC data field
    LC: list = [len(DATA)] if len(DATA) else []

    # transmit data
    data, sw1, sw2 = conn.transmit([0x00] + [INS] + P12 + LC + DATA)

    # error checking and return data
    if sw1 != 0x90:
        print(f"Error response: {sw1:02x} {sw2:02x}")
    return data, sw1, sw2


if __name__ == "__main__":
    # get readers and connect to card
    conn: CardConnectionDecorator = readers()[0].createConnection()
    conn.connect()

    # connect to app
    data, sw1, sw2 = transmit(conn, 0xA4, [0x04, 0x00], AID)
    print("\nApplet Selected!")

    # get hello world
    data, sw1, sw2 = transmit(conn, 0x40)
    print(list2bytes(data))

    # get parameters
    data, sw1, sw2 = transmit(conn, 0xEC, [0x00, 0x00])
    private_key: list = data
    data, sw1, sw2 = transmit(conn, 0xEC, [0x01, 0x00])
    public_key: list = data
    data, sw1, sw2 = transmit(conn, 0xEC, [0x06, 0x00])
    order: list = data
    print(f"\nECDSA keys:\npriv_key: {list2str(private_key)}\npubl_key: {list2str(public_key)}")

    # sign hash
    data, sw1, sw2 = transmit(conn, 0xEA, DATA=[0]*32)
    r, s = decode_asn1(data)
    print(f"\nSign hash:   {0}\nr:           {int2str(r, 64)}\ns:           {int2str(s,64)}")

    # calculate k
    k: int = ((pow(s, -1, list2int(order))) * (0 + r*list2int(private_key))) % list2int(order)
    print(f"\nDerive k:    {int2str(k,64)}")

    # use reference implementation to validate r and s
    pub_point: PointJacobi = PointJacobi(NIST256p, list2int(public_key[:32]), list2int(public_key[32:]), 1)
    publ: Public_key = Public_key(NIST256p.generator, pub_point)
    priv: Private_key = Private_key(publ, list2int(private_key))
    sign: Signature = priv.sign(hash=0, random_k=k)
    print(f"\nValidate with python reference implementation\nr (ref):     {int2str(sign.r, 64)}\ns (ref):     {int2str(sign.s,64)}")
    print(f"Signature is{'' if r == sign.r and s == sign.s else ' not'} properly calculated!")

    # verify signature
    message: list = [randint(0, 0xff) for i in range(32)]
    sha: HASH = sha256()
    sha.update(list2bytes(message))
    mhash: list = bytes2list(sha.digest())
    sign: Signature = priv.sign(list2int(mhash), k)
    signature: list = encode_asn1(sign.r, sign.s)

    data, sw1, sw2 = transmit(conn, 0xEB, [len(message), len(signature)], message + signature)
    print(f"\nSimulating a correct signature...\nSignature is classified as{'' if data[0] else ' not'} valid!")
