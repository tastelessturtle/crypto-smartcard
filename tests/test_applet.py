# installed modules
from smartcard.CardConnectionDecorator import CardConnectionDecorator

# custom modules
from constants import INS_HELLO_WORLD, AID
from communication import connect, select, transmit
from utils import list2bytes


def hello_world(conn: CardConnectionDecorator) -> None:
    """Requests hello from the smartcard.

    Args:
        conn (CardConnectionDecorator): The smartcard connection object.
    """
    # get hello world
    print("Request hello:")
    data, _, _ = transmit(conn, INS_HELLO_WORLD)
    print(list2bytes(data))
    assert list2bytes(data) == b'Hello World!', "Unexpected resonse in Hello World"


def test_applet() -> None:
    """Test the Applet in bare bones
    """
    # get readers and connect to card
    conn: CardConnectionDecorator = connect()
    select(conn, AID)

    # test hello world
    hello_world(conn)
