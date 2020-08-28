package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;

public class Helper {
	private static final CBORFactory factory = new CBORFactory();
	public static final int HASH_LENGTH = 32; // Since we use SHA256
	public static final byte[] EMPTY_BYTESTRING = new byte[]{0x40}; 
	public static final byte AEAD_ALGORITHM_ID = 0x10;
	public static final int AEAD_KEY_LENGTH = 16;
	public static final byte HMAC_ALGORITHM_ID = 0x5;
	public static final int AES_CCM_16_IV_LENGTH = 13;

	public static byte[] nextByteArray(CBORParser parser) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		parser.nextToken();
		parser.readBinaryValue( stream );
		return stream.toByteArray();
	}

	public static byte[] concat(byte[] a1, byte[] a2) {
		byte[] combined = new byte[a1.length + a2.length];
		int i = 0;
		for (byte b : a1) combined[i++] = b;
		for (byte b : a2) combined[i++] = b;
		return combined;
	}

	public static byte[] HMAC_SHA256(byte[] key) {
		return HMAC_SHA256(key, new byte[0]);
	}

	public static byte[] HMAC_SHA256(byte[] key, byte[] message) {
		byte opad = 0x5c;
		byte ipad = 0x36;

		if (key.length > HASH_LENGTH)
			key = SHA256(key);
		else if (key.length < HASH_LENGTH)
			key = pad(key, HASH_LENGTH);

		byte[] iKeyPad = xor(key, ipad);
		byte[] oKeyPad = xor(key, opad);

		return SHA256(concat(oKeyPad, SHA256(concat(iKeyPad, message))));
	}

	private static MessageDigest getSHA256Instance() {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch(Exception e) {
			System.out.println("SHA-256 for some reason not supported.");
			return null;
		}
		return md;
	
	}

	public static byte[] makeInfo(String algorithmId, int keyDataLength, byte[] th) {
		return makeInfo(algorithmId.getBytes(), keyDataLength, new byte[]{0x40}, th);
	}

	public static byte[] makeInfo(byte algorithmId, int keyDataLength, byte[] th) {
		return makeInfo(new byte[]{algorithmId}, keyDataLength, new byte[]{0x40}, th);
	}

	public static byte[] makeInfo(String algorithmId, int keyDataLength, byte[] protectedS, byte[] th) {
		return makeInfo(algorithmId.getBytes(), keyDataLength, protectedS, th);
	}

	// info = [
	// 	AlgorithmID,
	// 	[ null, null, null ],
	// 	[ null, null, null ],
	// 	[ keyDataLength, protected, other ]
	// ]
	public static byte[] makeInfo(byte[] algorithmID, int keyDataLength, byte[] protectedS, byte[] other) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try {
			CBORGenerator gen = factory.createGenerator(stream);
			gen.writeStartArray();
			gen.writeBinary(algorithmID);

			// Empty PartyUInfo
			gen.writeStartArray();
			gen.writeNull();
			gen.writeNull();
			gen.writeNull();
			gen.writeEndArray();

			// Empty PartyVInfo
			gen.writeStartArray();
			gen.writeNull();
			gen.writeNull();
			gen.writeNull();
			gen.writeEndArray();

			//SuppPubInfo
			gen.writeNumber(keyDataLength);
			gen.writeBinary(protectedS);
			gen.writeBinary(other);
			gen.writeEndArray();

			gen.close();
		} catch (IOException e) {
			System.out.println("Error occured couldn't create CBOR info context.");
		}

		return stream.toByteArray();
	}

	public static byte[] hkdf(int length, byte[] ikm, byte[] info) {
		byte[] prk = HMAC_SHA256(new byte[0], ikm);
		byte[] t = new byte[HASH_LENGTH];
		byte[] okm = new byte[length];
		int iters = (int) Math.ceil((double)length / HASH_LENGTH);
		for (int i = 0; i < iters; ++i) {
			t = HMAC_SHA256(prk, concat(concat(t, info), new byte[]{(byte)(1 + i)}));

			for (int j = 0; j < HASH_LENGTH && (j + i *HASH_LENGTH) < length; ++j) {
				okm[j + i * HASH_LENGTH] = t[j];
			}
		}
		return okm;
	}

	private static byte[] pad(byte[] key, int length) {
		byte[] paddedKey = new byte[length];
		int i = 0;
		for (byte b : key) paddedKey[i++] = b;
		return paddedKey;
	}

	public static byte[] xor(byte[] a1, byte[] a2) {
		if (a1.length != a2.length) throw new IllegalArgumentException("Can't XOR different sized arrays");
		
		byte[] result = new byte[a1.length];
		for (int i = 0; i < a1.length; ++i) 
		 	result[i] = (byte)(a1[i] ^ a2[i]);

		return result;
	}

	private static byte[] xor(byte[] val, byte pad) {
		byte[] result = new byte[val.length];
		int i = 0;
		for (Byte b : val) result[i++] = (byte)(b ^ pad);
		return result;
	}

	public static byte[] SHA256(byte[] data) {
		MessageDigest md = getSHA256Instance();
		return md.digest(data);
	}

	public static void printlnOnRead(String msg) {
		try {
			System.in.read();
		} catch (IOException _) {}
		System.out.println(msg);
	}


	// For K_2e
	// info = [
	//   "XOR-ENCRYPTION",
	//   [ null, null, null ],
	//   [ null, null, null ],
	//   [ plaintextLength, h'', TH_2 ]
	// ]
	public static byte[] makeK_2e(byte[] PRK_2e, byte[] TH_2, int length) {
		byte[] K_2e_info = makeInfo("XOR-ENCRYPTION", length, EMPTY_BYTESTRING, TH_2);
		return hkdf(length, PRK_2e, K_2e_info);
	}

	public static byte[] readSignature(byte[] plaintext) {
		byte[] signature = new byte[plaintext.length-1];
		for (int i = 1; i < plaintext.length; ++i) {
			signature[i-1] = plaintext[i];
		}
		return signature;
	}

	public static byte[] createData2(PublicKey G_Y, int C_R) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(G_Y.getEncoded());
		generator.writeNumber(C_R);
		generator.close();
		return stream.toByteArray();
	}
	public static byte[] makeK_3ae(byte[] PRK_3e2m, CBORObject protectedAttributes, byte[] TH_3) {
		byte[] K_3ae_info = makeInfo(new byte[]{AEAD_ALGORITHM_ID}, AEAD_KEY_LENGTH, protectedAttributes.EncodeToBytes(), TH_3);
		return hkdf(AEAD_KEY_LENGTH, PRK_3e2m, K_3ae_info);
	}

	public static byte[] makeIV_3ae(byte[] PRK_3e2m, CBORObject protectedAttributes, byte[] TH_3) {
		byte[] IV_3ae_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, protectedAttributes.EncodeToBytes(), TH_3);
		return hkdf(AES_CCM_16_IV_LENGTH, PRK_3e2m, IV_3ae_info);
	}
}