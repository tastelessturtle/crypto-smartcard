package xyz.tastelessturtle.javacard.cryptoapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;


class CryptoApplet extends Applet {

    private ECDSA ecdsa = null;

    private final static byte[] hello = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x74
    };

    protected CryptoApplet() {
        ecdsa = new ECDSA();
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    public void process(APDU apdu) {
		if (selectingApplet()) return;

        byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
            case (byte) 0x40:
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 12);
                apdu.sendBytesLong(hello , (short)0, (short) 12);
                break;
            
            case (byte) 0xEC:
                ecdsa.getConfig(apdu);
                break;

            case (byte) 0xEA:
                ecdsa.signHash(apdu);
                break;
            
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}