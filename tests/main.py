from smartcard.System import readers
from utils import list2bytes, str2list, list2str, int2str, list2int, bytes2list

from ecdsa.curves import NIST256p
from ecdsa.ecdsa import Public_key, Private_key
from ecdsa.ellipticcurve import PointJacobi

from asn1 import Decoder, Encoder


AID: list = str2list("5714e4720af2152cb449b1d8")


def transmit(conn, INS, P12=[0, 0], DATA=[]):
    # construct LC data field
    LC = [len(DATA)] if len(DATA) else []

    # transmit data
    data, sw1, sw2 = conn.transmit([0x00] + [INS] + P12 + LC + DATA)

    # error checking and return data
    if sw1 != 0x90:
        print(f"Error response: {sw1:02x} {sw2:02x}")
    return data, sw1, sw2


def decode_asn1(data: list) -> tuple:
    # init decoder twice
    decoder = Decoder()

    # decode first time
    decoder.start(list2bytes(data))

    # second decoding
    decoder.start(decoder.read()[1])
    _, r = decoder.read()
    _, s = decoder.read()

    # return
    return r, s


def encode_asn1(r: int, s: int) -> list:
    # init encoder
    encoder: Encoder = Encoder()

    # first encoding
    encoder.start()
    encoder.write(r)
    encoder.write(s)
    temp: bytes = encoder.output()

    # second encoding
    encoder.start()
    encoder.write(temp, nr=16, typ=32, cls=0)

    # return output
    return bytes2list(encoder.output())


if __name__ == "__main__":
    # get readers and connect to card
    conn = readers()[0].createConnection()
    conn.connect()

    # connect to app
    data, sw1, sw2 = transmit(conn, 0xA4, [0x04, 0x00], AID)
    print("Applet Selected!")

    # get hello world
    data, sw1, sw2 = transmit(conn, 0x40)
    print(list2bytes(data))

    # get parameters
    private_key, sw1, sw2 = transmit(conn, 0xEC, [0x00, 0x00])
    public_key, sw1, sw2 = transmit(conn, 0xEC, [0x01, 0x00])
    order, sw1, sw2 = transmit(conn, 0xEC, [0x06, 0x00])
    print(f"\nECDSA keys:\npriv_key: {list2str(private_key)}\npubl_key: {list2str(public_key)}")

    # signhash
    data, sw1, sw2 = transmit(conn, 0xEA, DATA=[0]*32)
    r, s = decode_asn1(data)
    print(f"\nSign hash:   {0}\nr:           {int2str(r, 64)}\ns:           {int2str(s,64)}")

    # calculate k
    k = ((pow(s, -1, list2int(order))) * (0 + r*list2int(private_key))) % list2int(order)
    print(f"\nDerive k:    {int2str(k,64)}")

    # use reference implementation to validate r and s
    pub_point = PointJacobi(NIST256p, list2int(public_key[:32]), list2int(public_key[32:]), 1)
    publ = Public_key(NIST256p.generator, pub_point)
    priv = Private_key(publ, list2int(private_key))
    sign = priv.sign(hash=0, random_k=k)
    print(f"\nValidate with python reference implementation\nr (ref):     {int2str(sign.r, 64)}\ns (ref):     {int2str(sign.s,64)}")
    if r == sign.r and s == sign.s:
        print("Signature is properly calculated!")
    else:
        print("Signature is not properly calculated!")
