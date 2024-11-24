# installed modules
from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.CardConnectionDecorator import CardConnectionDecorator

# basic utils
from utils import str2list
from constants import INS_SELECT_APP, P1_SELECT_AID, SW1_GOOD, SW2_GOOD


def connect() -> CardConnectionDecorator:
    """Connect to a smartcard through a reader.

    Returns:
        CardConnectionDecorator: The connection object to the smartcard.
    """
    # get listof readers, if list is empty assert
    print("\nFinding smartcard readers...")
    reader_list: list = readers()
    assert len(reader_list) > 0, "No reader connected"
    for r in reader_list:
        print(f"  {r}")

    # connect to first reader
    conn: CardConnectionDecorator = reader_list[0].createConnection()
    try:
        conn.connect()
    except NoCardException:
        assert False, "No card in reader"

    # return object
    return conn


def select(conn: CardConnectionDecorator, AID: str) -> None:
    """Select an Applet on the smartcard.

    Args:
        conn (CardConnectionDecorator): The connection object to the smartcard.
        AID (str): The AID string of the applet.
    """
    # try to connect with target
    print("Selecting Applet...")
    transmit(conn, INS_SELECT_APP, [P1_SELECT_AID, 0x00], str2list(AID))


def transmit(conn: CardConnectionDecorator, INS: int, P12: list = [0, 0], DATA: list = [], logging: bool = False) -> tuple[list, int, int]:
    """Transmits an APDU packet to the smartcard given a connection.

    Args:
        conn (CardConnectionDecorator): The connection object to the smartcard.
        INS (int): The APDU instruction byte (in integer form).
        P12 (list, optional): The APDUparameters. Defaults to [0, 0].
        DATA (list, optional): The APDU data. Defaults to [].
        logging (bool, optional): Prints low level logging. Defaults to False.

    Returns:
        tuple[list, int, int]: APDU response tuple (data, sw1, sw2)
    """
    def print_transmit(apdu: list) -> None:
        """Print the low level transmission communication.

        Args:
            apdu (list): The APDU list
        """
        print(">>", end=" ")
        for ap in apdu:
            print(f"{ap:02X}", end=" ")
        print()

    def print_response(data: list, sw1: int, sw2: int) -> None:
        """Print the low level response communication

        Args:
            data (list): Data list
            sw1 (int): SW1 integer
            sw2 (int): SW2 integer
        """
        print("<<", end=" ")
        for d in data:
            print(f"{d:02X}", end=" ")
        print(f"[{sw1:02X} {sw2:02X}]")

        # construct LC data field
    LC: list = [len(DATA)] if len(DATA) else []

    # transmit data
    apdu: list = [0x00] + [INS] + P12 + LC + DATA
    if logging:
        print_transmit(apdu)
    data, sw1, sw2 = conn.transmit(apdu)
    if logging:
        print_response(data, sw1, sw2)
    assert sw1 == SW1_GOOD and sw2 == SW2_GOOD

    # return data
    return data, sw1, sw2
