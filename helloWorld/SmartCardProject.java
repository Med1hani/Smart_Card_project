package helloWorld;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.framework.OwnerPIN;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;

public class SmartCardProject extends Applet
{
	/// INS code for each APDU
	
	private static final byte INST_HELLO = 0x10;//msg
	private static final byte INST_AUTH = 0x20;//pin
	private static final byte INST_LOCK = 0x21; //lock card
	private static final byte INST_GET_PUB_KEY = 0x30;
	private static final byte INST_SIGN_MSG = 0x31;
	
	
	public static final short DEFAULT_PIN_CODE = 0000;
	private static final short PIN_MAX_RETRIES = 50;
	private static final short PIN_SIZE = 4;
	
	private final static byte[] HELLO_STR =
	{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x73, 0x69, 0x72};//68 65 6c 6c 6f 20 73 69 72
	
	private final static byte[] OK_RESPONSE = {'O', 'K'};
	private final static byte[] KO_RESPONSE = {'K', 'O'};
	private final static byte[] OO_RESPONSE = {'O', 'O'};
	
	private javacard.security.RSAPublicKey publicRSAKey = null;
	private javacard.security.RSAPrivateKey privateRSAKey = null;
	private short pinCode = DEFAULT_PIN_CODE;
	private boolean cardConnected = false;
	
	private OwnerPIN ownerPin;
	private Signature rsaSignature;
	
	public static void install(byte[] buffer, short offset, byte length)
	{
		// new card 
		SmartCardProject smartCardProject = new SmartCardProject();
		smartCardProject.register();
		//generating the key pair
		KeyPair kpg = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
		kpg.genKeyPair();
		smartCardProject.publicRSAKey = (RSAPublicKey)kpg.getPublic();
		smartCardProject.privateRSAKey = (RSAPrivateKey)kpg.getPrivate();
		
	}
	
	SmartCardProject()
	{
		ownerPin = new OwnerPIN((byte)PIN_MAX_RETRIES, (byte)PIN_SIZE);
				        //rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_ISO9796, false);
       			//rsaSignature.init(privateRSAKey, Signature.MODE_SIGN);
	}

	public void process(APDU apdu) {
		
		if (selectingApplet()) {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}

		byte[] apduBuffer = apdu.getBuffer();
		
		// data
		if ((apduBuffer[ISO7816.OFFSET_CLA] == 0) && (apduBuffer[ISO7816.OFFSET_INS] == (byte) 0xA4)) {
            		return;
        	}

        	if (apduBuffer[ISO7816.OFFSET_CLA] != 0x0) {
            		ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        	}
		
		
		short bytesLeft = Util.makeShort((byte) 0x00, apduBuffer[ISO7816.OFFSET_LC]);
        	if (bytesLeft != apdu.setIncomingAndReceive()) {
            		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	}
		
		switch (apduBuffer[ISO7816.OFFSET_INS]) {
		case INST_HELLO:
			instHello(apdu);
			break;
		case INST_AUTH:
			instAuth(apdu);
			break;
		case INST_LOCK:
			instLock(apdu);
			break;
		case INST_GET_PUB_KEY:
			instGetPubKey(apdu);
			break;
		case INST_SIGN_MSG:
			instSignMsg(apdu);
			break;
		/////case okhra lhna w mtnsech l msg
		default:
			
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	///methods
	
	private void instHello(APDU apdu)
	{
		sendAPDUResponse(apdu, HELLO_STR);
	}
	
	private void instAuth(APDU apdu) // TODO: error message more clear
	{
		if (ownerPin.isValidated())
		{
			sendAPDUResponse(apdu, OK_RESPONSE);
			return;
		}
		if (ownerPin.getTriesRemaining() == 0)
		{
			sendAPDUResponse(apdu, OO_RESPONSE);
			return;
		}
		
		byte[] apduBuffer = apdu.getBuffer();
		
		if (apduBuffer[ISO7816.OFFSET_LC] != PIN_SIZE) {
            		sendAPDUResponse(apdu, KO_RESPONSE);
			return;
        	}
        	
        	if (ownerPin.check(apduBuffer, ISO7816.OFFSET_CDATA, (byte)PIN_SIZE))
        	{
        		sendAPDUResponse(apdu, OK_RESPONSE);
			return;
        	}
        	
        	// incorrect code 
		sendAPDUResponse(apdu, KO_RESPONSE);
	}
	
	private void instLock(APDU apdu)
	{
		// secuirty good use to protect the card .
		
		checkAuthenticated();
		ownerPin.reset();
		
		sendAPDUResponse(apdu, OK_RESPONSE);
	}
	
	private void instGetPubKey(APDU apdu)
	{
		checkAuthenticated();
	        byte[] apduBuffer = apdu.getBuffer();
        	short bufferDataOffset = ISO7816.OFFSET_CDATA;
        	
        	short pubKeyExponentSize = publicRSAKey.getExponent(apduBuffer, (short) (2 + bufferDataOffset));
        	
        	Util.setShort(apduBuffer, bufferDataOffset, pubKeyExponentSize);
        	
        	short pubKeyModulusSize = publicRSAKey.getModulus(apduBuffer, (short) (2 + bufferDataOffset + 2 + pubKeyExponentSize));
        	Util.setShort(apduBuffer, (short) (bufferDataOffset + 2 + pubKeyExponentSize), pubKeyModulusSize);
        	apdu.setOutgoingAndSend(bufferDataOffset, (short) (2 + pubKeyExponentSize + 2 + pubKeyModulusSize));
	}
	
  private void instSignMsg(APDU apdu) {
    checkAuthenticated();
    byte[] apduBuffer = apdu.getBuffer();
    short msgSize = apduBuffer[ISO7816.OFFSET_LC];

    byte[] tmpMsgCopy = new byte[msgSize];
    Util.arrayCopy(apduBuffer, (short) ISO7816.OFFSET_CDATA, tmpMsgCopy, (short) 0, (short) msgSize);

    Signature rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    rsaSignature.init(privateRSAKey, Signature.MODE_SIGN);

    short signSize = rsaSignature.sign(tmpMsgCopy, (short) 0, (short) tmpMsgCopy.length, apduBuffer, ISO7816.OFFSET_CDATA);
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signSize);
}
	
	
	
	private void sendAPDUResponse(APDU apdu, byte[] response)
	{
		byte[] buf = apdu.getBuffer();
		Util.arrayCopy(response, (short)0, buf, ISO7816.OFFSET_CDATA, (short)response.length);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)response.length);
	}
	
	
	private void checkAuthenticated()
	//verification de pin 
	{
        	if (!ownerPin.isValidated())
        	{
        		ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        	}
    	}
}
