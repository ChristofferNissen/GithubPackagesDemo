package edhoc;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

public class ECDiffieHellman {

    private KeyPairGenerator kpg;

    public ECDiffieHellman(int keysize) throws NoSuchAlgorithmException {
        kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(keysize);
    }

    public KeyPair generateKeyPair() {
        return kpg.generateKeyPair();
    }

    public PublicKey decodePublicKey(byte[] key) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(key);
            return kf.generatePublic(pkSpec);
        } catch (Exception _) {
            return null;
        }
    }

    public byte[] generateSecret(PrivateKey sk, PublicKey pk) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(sk);
            ka.doPhase(pk, true);
            return ka.generateSecret();
        } catch (Exception _) {
            return null;
        }
    }

}
