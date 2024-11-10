from time import time
from tqdm import trange
from smartcard.System import readers


AID: list = [
    0x57, 0x14, 0xe4, 0x72, 0x0a, 0xf2,
    0x15, 0x2c, 0xb4, 0x49, 0xb1, 0xd8
]

if __name__ == "__main__":
    # get readers and connect to card
    conn = readers()[0].createConnection()
    conn.connect()

    # connect to app
    command = [0x00, 0xA4, 0x04, 0x00, len(AID)] + AID
    data, sw1, sw2 = conn.transmit(command)
    print("%02x %02x" % (sw1, sw2))

    # get hello world
    command = [0x00, 0x40, 0x00, 0x00]
    data, sw1, sw2 = conn.transmit(command)
    print(data)
    print("%02x %02x" % (sw1, sw2))

    # get configurations
    pars = ["Private Key", "Public Key", "Field", "A", "B", "G", "R"]
    for P1 in range(7):
        command = [0x00, 0xEC, P1, 0x00]
        data, sw1, sw2 = conn.transmit(command)
        print(pars[P1], "".join(f"{x:02x}" for x in data))
        print("%02x %02x" % (sw1, sw2))

    # get speed of applet
    N = 1_000
    start_time: float = time()
    for i in trange(N):
        data, sw1, sw2 = conn.transmit(command)
    elapsed_time: float = time()-start_time
    print(f"Elapsed time: {elapsed_time:.2f} s")
    print(f"Time per cmd: {elapsed_time/N*1000:.4f} ms")

    # test signing once
    HASH = [0] * 32
    command = [0x00, 0xEA, 0x00, 0x00, len(HASH)]
    data, sw1, sw2 = conn.transmit(command + HASH)
    print("Sign data: ", "".join(f"{x:02x}" for x in data))
    print("%02x %02x" % (sw1, sw2))

    # sign data
    N = 100
    start_time: float = time()
    for i in trange(N):
        HASH = [0] * 32
        command = [0x00, 0xEA, 0x00, 0x00, len(HASH)]
        data, sw1, sw2 = conn.transmit(command + HASH)
    elapsed_time: float = time()-start_time
    print(f"Elapsed time: {elapsed_time:.2f} s")
    print(f"Time per cmd: {elapsed_time/N*1000:.4f} ms")
