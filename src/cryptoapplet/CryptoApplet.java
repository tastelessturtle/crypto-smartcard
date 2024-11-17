package cryptoapplet;

// javacard framework
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

class CryptoApplet extends Applet {

    // instructions
    private final byte INS_HELLO_WORLD = (byte) 0x40;
    private final byte INS_ECDSA_SIGN = (byte) 0xEA;
    private final byte INS_ECDSA_VERIFY = (byte) 0xEB;
    private final byte INS_ECDSA_CONFIG = (byte) 0xEC;
    private final byte INS_ECDSA_GENKEY = (byte) 0xED;

    // constants
    private final short SHORT0 = 0;

    // ECDSA object
    private ECDSA ecdsa = null;

    // Hello world string
    private final byte[] HELLOSTR = {
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21
    };
    private final short HELLOLEN = 12;

    /**
     * Constructor of the applet which initializes the crypto objects.
     */
    protected CryptoApplet() {
        // build ECDSA object
        ecdsa = new ECDSA();

        // register app
        register();
    }

    /**
     * Installs the applet on the smartcard.
     * 
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray The
     *                maximum value of bLength is 127.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet();
    }

    /**
     * Function to process the incoming APDU messages.
     * 
     * @param apdu the incoming APDU object
     */
    public void process(APDU apdu) {
        // return 9000 when app is selected
        if (selectingApplet())
            return;

        // read buffer and switch based on instruction
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            // simple hello world command
            case INS_HELLO_WORLD:
                apdu.setOutgoing();
                apdu.setOutgoingLength(HELLOLEN);
                apdu.sendBytesLong(HELLOSTR, SHORT0, HELLOLEN);
                break;

            // sign a 256bit hash
            case INS_ECDSA_SIGN:
                ecdsa.signHash(apdu);
                break;

            // verify a signature
            case INS_ECDSA_VERIFY:
                ecdsa.verifySignature(apdu);
                break;

            // get ecdsa parameters command
            case INS_ECDSA_CONFIG:
                ecdsa.getConfig(apdu);
                break;

            // generate a new keypair
            case INS_ECDSA_GENKEY:
                ecdsa.genKey(apdu);
                break;

            // other instructions are not supported
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
}