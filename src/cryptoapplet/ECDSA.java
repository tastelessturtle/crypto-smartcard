package cryptoapplet;

// javacard framework packages
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

// javacard security packages
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

class ECDSA {

    // instruction connstants
    private final byte PAR_PRIVATE = 0x00;
    private final byte PAR_PUBLIC = 0x01;
    private final byte PAR_FIELD = 0x02;
    private final byte PAR_A = 0x03;
    private final byte PAR_B = 0x04;
    private final byte PAR_G = 0x05;
    private final byte PAR_R = 0x06;

    // NIST P256 curve configuration
    private final byte[] P256_FIELD = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };
    private final byte[] P256_A = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };
    private final byte[] P256_B = {
            (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
            (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
            (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
            (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
    };
    private final byte[] P256_G = {
            (byte) 0x04,
            (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
            (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
            (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
            (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
            (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
            (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
            (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
            (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
    };
    private final byte[] P256_R = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
            (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
    };

    // default keys to test with
    private final byte[] defaultPrivateKey = {
            (byte) 0x65, (byte) 0x42, (byte) 0x7b, (byte) 0x12, (byte) 0xcf, (byte) 0x91, (byte) 0xf3, (byte) 0x1e,
            (byte) 0x4f, (byte) 0xf7, (byte) 0x55, (byte) 0x51, (byte) 0x68, (byte) 0xf7, (byte) 0x0f, (byte) 0xfe,
            (byte) 0x07, (byte) 0xbd, (byte) 0x72, (byte) 0x3f, (byte) 0x94, (byte) 0x67, (byte) 0x7a, (byte) 0x2a,
            (byte) 0x52, (byte) 0x6b, (byte) 0x9f, (byte) 0xed, (byte) 0xb6, (byte) 0xbc, (byte) 0x13, (byte) 0xa6
    };
    private final byte[] defaultPublicKey = {
            (byte) 0x04,
            (byte) 0x72, (byte) 0x9f, (byte) 0x6f, (byte) 0x01, (byte) 0x07, (byte) 0x2e, (byte) 0x34, (byte) 0x18,
            (byte) 0xbe, (byte) 0xd3, (byte) 0xcc, (byte) 0xdf, (byte) 0x1d, (byte) 0xb0, (byte) 0xed, (byte) 0x8b,
            (byte) 0x76, (byte) 0xad, (byte) 0x38, (byte) 0xb2, (byte) 0x9a, (byte) 0xce, (byte) 0xce, (byte) 0x53,
            (byte) 0x92, (byte) 0x8d, (byte) 0xe4, (byte) 0xf3, (byte) 0xf8, (byte) 0xec, (byte) 0x76, (byte) 0x00,
            (byte) 0xc3, (byte) 0x9a, (byte) 0xe0, (byte) 0xf5, (byte) 0x71, (byte) 0x6c, (byte) 0x29, (byte) 0x9c,
            (byte) 0xfe, (byte) 0x21, (byte) 0xb2, (byte) 0x38, (byte) 0xaf, (byte) 0x65, (byte) 0xe9, (byte) 0x01,
            (byte) 0xf7, (byte) 0x3a, (byte) 0x3d, (byte) 0xd1, (byte) 0xa0, (byte) 0xa6, (byte) 0x6e, (byte) 0x2f,
            (byte) 0x17, (byte) 0x99, (byte) 0xae, (byte) 0x0e, (byte) 0xbc, (byte) 0x22, (byte) 0xa6, (byte) 0x2b
    };

    // object variables
    private Signature sign = null;
    private Signature verify = null;
    private KeyPair keyPair = null;
    private ECPrivateKey privateKey = null;
    private ECPublicKey publicKey = null;

    /**
     * Constructor which configures the keypair and initializes the signatures.
     */
    public ECDSA() {
        // build private key
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256,
                false);
        privateKey.setS(defaultPrivateKey, (short) 0, (short) defaultPrivateKey.length); // default private key
        privateKey.setFieldFP(P256_FIELD, (short) 0, (short) P256_FIELD.length); // prime p
        privateKey.setA(P256_A, (short) 0, (short) P256_A.length); // first coefficient
        privateKey.setB(P256_B, (short) 0, (short) P256_B.length); // second coefficient
        privateKey.setG(P256_G, (short) 0, (short) P256_G.length); // base point G
        privateKey.setR(P256_R, (short) 0, (short) P256_R.length); // order of base point

        // build public key
        publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        publicKey.setW(defaultPublicKey, (short) 0, (short) defaultPublicKey.length); // default public key
        publicKey.setFieldFP(P256_FIELD, (short) 0, (short) P256_FIELD.length); // prime p
        publicKey.setA(P256_A, (short) 0, (short) P256_A.length); // first coefficient
        publicKey.setB(P256_B, (short) 0, (short) P256_B.length); // second coefficient
        publicKey.setG(P256_G, (short) 0, (short) P256_G.length); // base point G
        publicKey.setR(P256_R, (short) 0, (short) P256_R.length); // order of base point

        // make keyPair
        keyPair = new KeyPair(publicKey, privateKey);

        // build signing signature
        sign = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sign.init(privateKey, Signature.MODE_SIGN);

        // build verifying signature
        verify = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        verify.init(publicKey, Signature.MODE_VERIFY);
    }

    /**
     * Responds with the configuration of the ECDSA keys and parameters.
     * 
     * @param apdu the incoming APDU object
     * @throws ISOException when an incorrect parameter is given
     */
    public void getConfig(APDU apdu) throws ISOException {
        // get buffer
        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();

        // switch based on P1 for type of paramerer
        byte P1 = buffer[ISO7816.OFFSET_P1];
        switch (P1) {
            case PAR_PRIVATE:
                le = privateKey.getS(buffer, (short) 0);
                break;
            case PAR_PUBLIC:
                le = publicKey.getW(buffer, (short) 0);
                break;
            case PAR_FIELD:
                le = publicKey.getField(buffer, (short) 0);
                break;
            case PAR_A:
                le = publicKey.getA(buffer, (short) 0);
                break;
            case PAR_B:
                le = publicKey.getB(buffer, (short) 0);
                break;
            case PAR_G:
                le = publicKey.getG(buffer, (short) 0);
                break;
            case PAR_R:
                le = publicKey.getR(buffer, (short) 0);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }

        // return response and remove uncompressed tag for 256 bit data
        if (P1 == PAR_PUBLIC || P1 == PAR_G) {
            apdu.setOutgoingLength((short) (le - 1));
            apdu.sendBytes((short) 1, (short) (le - 1));
        } else {
            apdu.setOutgoingLength(le);
            apdu.sendBytes((short) 0, le);
        }
    }

    /**
     * Signs a hash.
     * 
     * @param apdu the incoming APDU object
     * @throws ISOException when the incoming data is of incorrect length
     */
    public void signHash(APDU apdu) throws ISOException {
        // get buffer and check if incoming data is 32 bytes long
        byte[] buffer = apdu.getBuffer();
        short lc = (short) buffer[ISO7816.OFFSET_LC];
        if (lc != 32)
            ISOException.throwIt((short) 0x6720);
        short le = apdu.setOutgoing();

        // try to sign
        try {
            le = sign.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, lc, buffer, (short) 0);
        } catch (CryptoException e) {
            CryptoException.throwIt(e.getReason());
        }

        // return response
        apdu.setOutgoingLength(le);
        apdu.sendBytes((short) 0, le);
    }

    public void verifySignature(APDU apdu) {
        // get length and offsets of data
        byte[] buffer = apdu.getBuffer();
        byte inOffset = ISO7816.OFFSET_CDATA;
        byte inLength = buffer[ISO7816.OFFSET_P1];
        byte sigOffset = (byte) (inOffset + inLength);
        byte sigLength = buffer[ISO7816.OFFSET_P2];

        // try to verify
        try {
            boolean isValid = verify.verify(buffer, inOffset, inLength, buffer, sigOffset, sigLength);
            buffer[0] = isValid ? (byte) 1 : (byte) 0;
        } catch (CryptoException e) {
            CryptoException.throwIt(e.getReason());
        }

        // send response with length
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        apdu.sendBytes((short) 0, (short) 1);
    }

    /**
     * Generates a new keypair.
     * 
     * @param apdu the incoming APDU object
     */
    public void genKey(APDU apdu) {
        // gen new keypair
        keyPair.genKeyPair();
        privateKey = (ECPrivateKey) keyPair.getPrivate();
        publicKey = (ECPublicKey) keyPair.getPublic();

        // return with okay
        apdu.setOutgoingLength((short) 0);
        apdu.sendBytes((short) 0, (short) (0));
    }
}