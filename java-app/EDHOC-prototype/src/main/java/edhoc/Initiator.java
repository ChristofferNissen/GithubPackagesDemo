package edhoc;

import java.security.KeyPair;
import java.security.PublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.*;

public class Initiator {
	private static final CBORFactory factory = new CBORFactory();

	// Cipher Suite consists of: 
	//	* AEAD Algorithm
	//	* Hash Algorithm
	//	* Elliptic Curve
	//	* Signature Algorithm
	//	* Signature Algorithm Curve
	//	* AEAD algorithm
	//	* Application Hash Algorithm
	// Represents a specific suite consisting of an ordered set of COSE algorithms
	int method = 0; // Initiator and Responder both use Signature Key
	int corr = 3; // transport provides a correlation mechanism that enables both parties to correlate all three messages
	int SUITE_I = 2; // (AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256)
	int METHOD_CORR; // Method and correlation as a single value (specified in message_1)
	int C_I = 5; // bstr / int
	ECDiffieHellman dh;
	PublicKey G_X;
	byte[] G_XY = null;
	byte[] ID_CRED_R = new byte[]{0x14};
	byte[] ID_CRED_I = new byte[]{0x23};
	byte[] CRED_R; 
	byte[] CRED_I;
	byte[] message1 = null;
	KeyPair keyPair; // Pair of values for G_X and the private component
	OneKey signatureKey;
	OneKey verificationKey;

	public Initiator(ECDiffieHellman dh, KeyPair signatureKeyPair, PublicKey responderPk) throws CoseException {
		METHOD_CORR = 4 * method + corr;
		this.dh = dh;
		CRED_R = responderPk.getEncoded();
		keyPair = dh.generateKeyPair();
		G_X = keyPair.getPublic();
		CRED_I = signatureKeyPair.getPublic().getEncoded();
		signatureKey = new OneKey(signatureKeyPair.getPublic(), signatureKeyPair.getPrivate());
		verificationKey = new OneKey(responderPk, null);
		
		Helper.printlnOnRead("Setting up Initiator before protocol..");
		System.out.println("Initiator chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()) + "\n");
		System.out.println("Initiator public key " + G_X + "\nEmphemeral ECDH key pair constructed\n");
	}

	// The Initiator SHALL compose message_1 as follows:
	// The supported cipher suites and the order of preference MUST NOT be changed
	// based on previous error messages. However, the list SUITES_I sent to the
	// Responder MAY be truncated such that cipher suites which are the least
	// preferred are omitted. The amount of truncation MAY be changed between
	// sessions, e.g. based on previous error messages (see next bullet), but all
	// cipher suites which are more preferred than the least preferred cipher suite
	// in the list MUST be included in the list.
	// Determine the cipher suite to use with the Responder in message_1. If the
	// Initiator previously received from the Responder an error message to a
	// message_1 with diagnostic payload identifying a cipher suite that the
	// Initiator supports, then the Initiator SHALL use that cipher suite. Otherwise
	// the first supported (i.e. the most preferred) cipher suite in SUITES_I MUST
	// be used.
	// Generate an ephemeral ECDH key pair as specified in Section 5 of [SP-800-56A]
	// using the curve in the selected cipher suite and format it as a COSE_Key. Let
	// G_X be the 'x' parameter of the COSE_Key.
	// Choose a connection identifier C_I and store it for the length of the
	// protocol.
	// Encode message_1 as a sequence of CBOR encoded data items as specified in
	// Section 4.2.1
	public byte[] createMessage1() throws IOException {
		Helper.printlnOnRead("Initiator Processing of Message 1");
		Helper.printlnOnRead("	Picking method = 0 (both parties know each others public key)");
		Helper.printlnOnRead("	Picking correlation = 3 (underlying TCP like connection exists)");
		Helper.printlnOnRead("	Connection identifier C_I(" + C_I + ") chosen");
	 	Helper.printlnOnRead("	Cipher suite 2 selected");
		Helper.printlnOnRead("	CBOR Object created... Sending message...");

		// Encode and send
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeNumber(METHOD_CORR);
		generator.writeNumber(SUITE_I);
		generator.writeBinary(G_X.getEncoded());
		generator.writeNumber(C_I);
		generator.close();
		message1 = stream.toByteArray();
		return message1;
	}

	// Receive message 2, make and return message 3
	public byte[] createMessage3(byte[] message2) throws IOException, CoseException{
		Helper.printlnOnRead("Initiator Processing of Message 2");

		// Decoding
		CBORParser parser = factory.createParser(message2);
		byte[] pk = nextByteArray(parser);
		int c_r = parser.nextIntValue(-1);
		byte[] CIPHERTEXT_2 = nextByteArray(parser);
		parser.close();

		G_XY = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));


		Helper.printlnOnRead("	Decoded message two successfully..");
		Helper.printlnOnRead("	Protocol state retrieved");
		Helper.printlnOnRead("	Initiator has shared secret: 0x" + printHexBinary(G_XY));
		
		byte[] data2 = createData2(c_r, pk);
		byte[] TH_2 = SHA256(concat(message1, data2));
		byte[] PRK_2e = HMAC_SHA256(G_XY); 
		byte[] K_2e = makeK_2e(PRK_2e, TH_2, CIPHERTEXT_2.length); 
		byte[] plaintext = xor(K_2e, CIPHERTEXT_2); // Decrypt

		Helper.printlnOnRead("	Ciphertext decrypted = 0x" + printHexBinary(plaintext) );
		Helper.printlnOnRead("	Correctly identified the other party: " + (plaintext[0] == ID_CRED_R[0]) );
		Helper.printlnOnRead("	Initator connects id 0x" + printHexBinary(ID_CRED_R) + " to key 0x" + printHexBinary(CRED_R));

		// Validate signature 
		Sign1Message M = (Sign1Message) Sign1Message.DecodeFromBytes(readSignature(plaintext));
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		M.setExternal( concat(TH_2, CRED_R) ); // external_aad = << TH_2, CRED_R >>

		Helper.printlnOnRead( "	Signature is valid: " + M.validate(verificationKey) );
		Helper.printlnOnRead("Initiator Processing of Message 3");
		Helper.printlnOnRead("	Transcript Hash (TH_3) computed");

		byte[] TH_3 = SHA256(concat(TH_2, CIPHERTEXT_2));
		// Used to encrypt message_3
		byte[] PRK_3e2m = PRK_2e; // Since we don't use static Diffie-Hellman key
		// Used to derive keys and IVs to produce a MAC in message_3 and to
		// derive application specific data
		byte[] PRK_4x3m = PRK_3e2m; // Since we don't use static Diffie-Hellman key

		// Compute an inner COSE_Encrypt0 as defined in Section 5.3 of [RFC8152], with
		// the EDHOC AEAD algorithm in the selected cipher suite, K_3m IV_3m and the 
		// following parameters: (Omitted)
		// MAC_3 is the 'ciphertext' of the inner COSE_Encrypt0.
		Encrypt0Message inner = new Encrypt0Message();
		inner.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);
		inner.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_I), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		inner.setExternal( concat(TH_3, CRED_I) ); // external_aad = << TH_3, CRED_I >>
		inner.SetContent(""); // plaintext = h''

		// Nonce N = IV_3m is th output of HKDF-Expand(PRK_4x3m, info, L)	
		byte[] IV_3m = makeIV_3m(PRK_4x3m, inner.getProtectedAttributes(), TH_3);
		inner.addAttribute(HeaderKeys.IV, IV_3m, Attribute.DO_NOT_SEND);

		// K_3m s
		byte[] K_3m = makeK_3m(PRK_4x3m, inner.getProtectedAttributes(), TH_3);
		inner.encrypt(K_3m);

		// If the Initiator authenticates with a static Diffie-Hellman key (method equals 2 or 3)
		// then the Signature_or_MAC_3 is MAC_3.
		byte[] MAC_3 = inner.EncodeToBytes();
		Helper.printlnOnRead("	MAC_3 calculated = 0x" + printHexBinary(MAC_3) );

		M = new Sign1Message();
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		M.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_I), Attribute.PROTECTED); // protected = << ID_CRED_I >>
		M.setExternal( concat(TH_3, CRED_I) ); // << TH_3, CRED_I >>
		M.SetContent(MAC_3); // payload
		M.sign(signatureKey);

		byte[] signature = M.EncodeToBytes();


		Helper.printlnOnRead("	MAC_3 signed = 0x" + printHexBinary(signature) );

		// Compute an outer COSE_Encrypt0 as defined in Section 5.3
		// CIPHERTEXT_3 is the 'ciphertext' of the outer COSE_Encrypt0
		Encrypt0Message outer = new Encrypt0Message();
		outer.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND); // AEAD Algorithm
		outer.setExternal(TH_3); // external_aad = TH_3
		outer.SetContent( concat(ID_CRED_I, signature) ); // plaintext = ( ID_CRED_I / bstr_identifier, Signature_or_MAC_3, ? AD_3 )
		
		// Nonce IV_3ae is the output of HKDF-Expand(PRK_3e2m, info, L). PRK_3e2m = PRK_2e for asymmetric
		byte[] IV_3ae = makeIV_3ae(PRK_3e2m, outer.getProtectedAttributes(), TH_3);
		outer.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_3ae), Attribute.DO_NOT_SEND);
		byte[] K_3ae = makeK_3ae(PRK_3e2m, outer.getProtectedAttributes(), TH_3);
		outer.encrypt(K_3ae);

		byte[] CIPHERTEXT_3 = outer.EncodeToBytes();
		Helper.printlnOnRead("	CIPHERTEXT_3 computed");

		// Encode message3 as a sequence of CBOR encoded data items as specified in Section 4.4.1
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(CIPHERTEXT_3);
		generator.close();
		byte[] s = stream.toByteArray();

		Helper.printlnOnRead("	message_3 encoded as CBOR");
		return s;
	}

	private byte[] makeK_3m(byte[] PRK_4x3m, CBORObject protectedAttributes, byte[] TH_3) {
		byte[] K_3m_info = makeInfo(new byte[]{AEAD_ALGORITHM_ID}, AEAD_KEY_LENGTH, protectedAttributes.EncodeToBytes(), TH_3); 
		return hkdf(AEAD_KEY_LENGTH, PRK_4x3m, K_3m_info);
	}

	private byte[] makeIV_3m(byte[] PRK_4x3m, CBORObject protectedAttributes, byte[] TH_3) {
		byte[] IV_3m_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, protectedAttributes.EncodeToBytes(), TH_3);
		return hkdf(AES_CCM_16_IV_LENGTH, PRK_4x3m, IV_3m_info);
	}

	private byte[] createData2(int c_r, byte[] pk) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(pk);
		generator.writeNumber(c_r);
		generator.close();
		return stream.toByteArray();
	}

}
