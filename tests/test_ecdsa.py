# built-in modules
from random import randint
from hashlib import sha256

# installed modules
from smartcard.CardConnectionDecorator import CardConnectionDecorator

# ECDSA module
from ecdsa.curves import NIST256p
from ecdsa.ecdsa import Public_key, Private_key, Signature
from ecdsa.ellipticcurve import PointJacobi

# custom modules
from constants import AID, INS_ECDSA_CONFIG, INS_ECDSA_GENKEY, INS_ECDSA_SIGN_MESSAGE, INS_ECDSA_VERIFY
from constants import PAR_SECRET, PAR_PUBLIC, PAR_FIELD, PAR_A, PAR_B, PAR_G, PAR_R
from communication import connect, select, transmit
from utils import list2int, list2str, int2str, list2bytes, bytes2int
from utils import decode_asn1, encode_asn1


def check_NIST_parameters(conn: CardConnectionDecorator):
    """Check if the parameters on the card are of the NIST-P256 curve.

    Args:
        conn (CardConnectionDecorator): Smartcard connection object.
    """
    # get field, A, B, G and R
    p_field, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_FIELD, 0x00])
    p_a, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_A, 0x00])
    p_b, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_B, 0x00])
    p_g, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_G, 0x00])
    p_r, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_R, 0x00])

    # assert if any are wrong
    print("Checking NIST-256P curve parameters...")
    assert NIST256p.curve.p() == list2int(p_field)
    assert NIST256p.curve.p() + NIST256p.curve.a() == list2int(p_a)
    assert NIST256p.curve.b() == list2int(p_b)
    assert NIST256p.generator.x() == list2int(p_g) >> 256
    assert NIST256p.generator.y() == list2int(p_g) % 2**256
    assert NIST256p.order == list2int(p_r)
    print("OK!")


def gen_and_get_keys(conn: CardConnectionDecorator) -> Private_key:
    """Generate new keys and read from smartcard.

    Args:
        conn (CardConnectionDecorator): The Smartcard connection object.

    Returns:
        Private_key: The private key object (containing public key)
    """
    # get private and public key
    print("Generating and reading keys...")
    transmit(conn, INS_ECDSA_GENKEY)
    private_key, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_SECRET, 0x00])
    public_key, _, _ = transmit(conn, INS_ECDSA_CONFIG, [PAR_PUBLIC, 0x00])
    print(f"Private key: {list2str(private_key)}\nPublic key:  {list2str(public_key)}")

    # parse to objects, use reference implementation to validate r and s
    public_point: PointJacobi = PointJacobi(NIST256p, list2int(public_key[:32]), list2int(public_key[32:]), 1)
    public: Public_key = Public_key(NIST256p.generator, public_point)
    private: Private_key = Private_key(public, list2int(private_key))

    # return keys
    return private


def sign_message(conn: CardConnectionDecorator, message: list) -> Signature:
    """Signs a message on the smartcard.

    Args:
        conn (CardConnectionDecorator): The smartcard connection object.
        message (list): The message to sign.

    Returns:
        Signature: The signature of the message.
    """
    # has and sign message
    print(f"Sign message {list2str(message)}")
    data, _, _ = transmit(conn, INS_ECDSA_SIGN_MESSAGE, DATA=message)

    # decode and create Signature object
    r, s = decode_asn1(data)
    signature: Signature = Signature(r, s)
    print(f"Signature:\nr: {int2str(signature.r, 64)}\ns: {int2str(signature.s, 64)}")

    # return signature
    return signature


def verify_signature(conn: CardConnectionDecorator, private: Private_key, message: list, signature: Signature):
    """Verify a signature with the smartcard and a reference implementation

    Args:
        conn (CardConnectionDecorator): The smartcard connection object.
        private (Private_key): The private key.
        message (list): The message to hash and verify.
        signature (Signature): The signature to verify.
    """
    # verify signature with smartcard
    signature_data: list = encode_asn1(signature.r, signature.s)
    print("Verifying Signature with SmartCard...")
    data, _, _ = transmit(conn, INS_ECDSA_VERIFY, [len(message), len(signature_data)], message + signature_data)
    print(f"{'OK!' if data[0] else 'FAIL!'}")

    # verify signature with reference implementation
    print("Verifying Signature with Reference...")
    hash_in: bytes = sha256(list2bytes(message)).digest()
    outcome: bool = private.public_key.verifies(bytes2int(hash_in), signature)
    print(f"{'OK!' if outcome else 'FAIL!'}")


def test_ecdsa():
    """Test the ECDSA functionality on the smartcard.
    """
    # get readers and connect to card
    conn: CardConnectionDecorator = connect()
    select(conn, AID)

    # check NIST curve and get keys
    check_NIST_parameters(conn)
    private: Private_key = gen_and_get_keys(conn)

    # sign random message (max 0x80-74 length because of verify with signature length)
    message: list = [randint(0, 0xFF) for _ in range(1, 0x80-74)]
    signature: Signature = sign_message(conn, message)

    # verify signature with smartcard and reference implementation
    verify_signature(conn, private, message, signature)
