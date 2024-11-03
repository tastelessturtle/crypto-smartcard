from smartcard.System import readers

if __name__ == "__main__":
    # get readers and connect to card
    conn = readers()[0].createConnection()
    conn.connect()

    # connect to app
    uid = [0x57, 0x14, 0xe4, 0x72, 0x0a, 0xf2,
           0x15, 0x2c, 0xb4, 0x49, 0xb1, 0xd8]
    command = [0x00, 0xA4, 0x04, 0x00, len(uid)] + uid
    data, sw1, sw2 = conn.transmit(command)
    print("%02x %02x" % (sw1, sw2))

    # get hello world
    command = [0x00, 0x40, 0x00, 0x00]
    data, sw1, sw2 = conn.transmit(command)
    print(data)
    print("%02x %02x" % (sw1, sw2))
