# import asn1 encoder and decoder
from asn1 import Decoder, Encoder


def list2str(lst: list) -> str:
    """Function to convert list to string.

    Args:
        lst (list): Input list.

    Returns:
        str: Output string.
    """
    return "".join([f"{x:02x}" for x in lst])


def list2bytes(lst: list) -> bytes:
    """Function to convert list to bytes.

    Args:
        lst (list): Input list.

    Returns:
        bytes: Output bytes.
    """
    return bytes(lst)


def list2int(lst: list) -> int:
    """Function to convert list to integer.

    Args:
        lst (list): Input list.

    Returns:
        int: Output integer.
    """
    return sum([x << (i*8) for i, x in enumerate(lst[::-1])])


def str2bytes(string: str) -> bytes:
    """Function to convert string to bytes.

    Args:
        string (str): Input string.

    Returns:
        bytes: Output bytes.
    """
    return bytes.fromhex(string)


def str2list(string: str) -> list:
    """Function to convert string to list.

    Args:
        string (str): Input string.

    Returns:
        list: Output list.
    """
    return [int(string[i*2:i*2+2], 16) for i in range(len(string)//2)]


def str2int(string: str) -> int:
    """Function to convert string to integer.

    Args:
        string (str): Input string.

    Returns:
        int: Output integer.
    """
    return int(string, 16)


def bytes2list(byt: bytes) -> list:
    """Function to convert bytes to list.

    Args:
        string (bytes): Input bytes.

    Returns:
        list: Output list.
    """
    return [x for x in byt]


def bytes2int(byt: bytes) -> int:
    """Function to convert bytes to integer.

    Args:
        string (bytes): Input bytes.

    Returns:
        int: Output integer.
    """
    return int.from_bytes(byt, 'big')


def bytes2str(byt: bytes) -> str:
    """Function to convert bytes to string.

    Args:
        string (bytes): Input bytes.

    Returns:
        str: Output string.
    """
    return byt.hex()


def int2str(integer: int, len: int = 32) -> str:
    """Function to convert integer to string.

    Args:
        integer (int): Input integer.
        len (int, optional): Length of the string in half bytes. Defaults to 32 (16 bytes).

    Returns:
        str: Output string.
    """
    return f"{integer:0{len}x}"


def int2bytes(integer: int, len: int = 16) -> bytes:
    """Function to convert integer to bytes.

    Args:
        integer (int): Input integer.
        len (int, optional): Length of the bytes in bytes. Defaults to 16.

    Returns:
        bytes: Output bytes.
    """
    return integer.to_bytes(len, 'big')


def int2list(integer: int, len: int = 16) -> list:
    """Functio to convert integer to list.

    Args:
        integer (int): Input integer.
        len (int, optional): Length of the list in bytes. Defaults to 16.

    Returns:
        list: Output list.
    """
    return [(integer >> (i*8)) & 0xff for i in range(len)[::-1]]


def decode_asn1(data: list) -> tuple[int, int]:
    """Function to decode ASN.1 encoded signature data.

    Args:
        data (list): Raw ASN.1 encoded signature list.

    Returns:
        tuple[int, int]: Output tuple containing Signature integers (r,s).
    """
    # init decoder twice
    decoder: Decoder = Decoder()

    # decode first time
    decoder.start(list2bytes(data))

    # second decoding
    decoder.start(decoder.read()[1])
    r: int = 0
    s: int = 0
    _, r = decoder.read()
    _, s = decoder.read()

    # return
    return r, s


def encode_asn1(r: int, s: int) -> list:
    """Function to encode (r,s) signature integer pair to a ASN.1 list.

    Args:
        r (int): R part of the signature.
        s (int): S part of the signature.

    Returns:
        list: Output ASN.1 encoded signature list.
    """
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
