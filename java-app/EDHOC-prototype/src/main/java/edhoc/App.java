package edhoc;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import COSE.CoseException;

public class App {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, CoseException {
        Security.addProvider(new BouncyCastleProvider());
 
        System.out.println( "" );
        System.out.println( "EDHOC PROTOTYPE" );
        System.out.println( "" );

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        KeyPair initiatorPair = kpg.generateKeyPair();
        KeyPair respoderPair = kpg.generateKeyPair();

        // Fixed parameters for our project
        ECDiffieHellman dh = new ECDiffieHellman(256); // Keysize 256 for P-256

        Initiator initiator = new Initiator(dh, initiatorPair, respoderPair.getPublic());
        Responder responder = new Responder(dh, respoderPair, initiatorPair.getPublic());

        byte[] message1 = initiator.createMessage1();
        System.out.println("    Initiator sends (" + message1.length + " bytes" +"): " + printHexBinary(message1) + "\n");

        byte[] message2 = responder.createMessage2(message1);
        System.out.println("    Responder sends (" + message2.length + " bytes" +"): " + printHexBinary(message2) + "\n");

        byte[] message3 = initiator.createMessage3(message2);
        System.out.println("    Initiator sends (" + message3.length + " bytes" +"): " + printHexBinary(message3) + "\n");

        responder.validateMessage3(message3);

    }

}
