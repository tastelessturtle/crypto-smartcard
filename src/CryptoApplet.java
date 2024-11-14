package xyz.tastelessturtle.javacard.cryptoapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

class CryptoApplet extends Applet {

    // ECDSA object
    private ECDSA ecdsa = null;

    private final static byte[] hello = {
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21
    };

    protected CryptoApplet() {
        // build ECDSA object
        ecdsa = new ECDSA();

        // register app
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    public void process(APDU apdu) {
        // return 9000 when app is selected
        if (selectingApplet())
            return;

        // read buffer and switch based on instruction
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            // simple hello world command
            case (byte) 0x40:
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 12);
                apdu.sendBytesLong(hello, (short) 0, (short) 12);
                break;

            // get ecdsa parameters command
            case (byte) 0xEC:
                ecdsa.getConfig(apdu);
                break;

            // sign a 256bit hash
            case (byte) 0xEA:
                ecdsa.signHash(apdu);
                break;

            // other instructions are not supported
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}