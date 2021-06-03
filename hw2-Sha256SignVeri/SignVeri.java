import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/*
carol>
openssl genrsa -out CarolPriv.pem 2048
openssl req -new -key CarolPriv.pem -out CarolCsr.pem -subj /CN=YOUR_NAME/
openssl x509 -req -days 365 -in CarolCsr.pem -signkey CarolPriv.pem -out CarolCert.pem
copy CarolCert.pem ..\Bob\

Alice>
openssl genrsa -out AlicePriv.pem 2048
openssl req -new -key AlicePriv.pem -out AliceCsr.pem -subj /CN=Alice/
copy AliceCsr.pem ..\Carol\

Carol>
openssl x509 -req -days 365 -CA CarolCert.pem -CAkey CarolPriv.pem -in AliceCsr.pem -out AliceCert.pem -CAcreateserial
copy AliceCert.pem ..\Alice\

Alice> openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in AlicePriv.pem -out AlicePriv.p8
Alice> java SignVeri sign AlicePriv.p8 msg.txt
Alice> copy msg.txt

Bob> type msg.txt
Bob> java SignVeri verify
Bob> openssl verify -CAfile CarolCert.pem AliceCert.pem

# print cert
keytool -printcert -file [x509]
openssl x509 -text -noout -in [x509]

# Convert pkcs1 to pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in AlicePriv.pem -out AlicePriv.p8

# X.509 chain verification
openssl verify -CAfile CarolCert.pem AliceCert.pem
*/

public class SignVeri {

    public static void main(String[] args) {
        try {

            if (args.length < 3) {
                System.out.println("Invalid arguments.");
                printHowToUse();
            } else if (args.length == 3 && args[0].equals("sign")) {
                generateSignature(args[1], args[2]);
            } else if (args.length == 4 && args[0].equals("verify")) {
                verifySignature(args[1], args[2], args[3]);
            } else {
                printHowToUse();
            }

        } catch(Exception e) {
            e.printStackTrace();
            printHowToUse();
        }
    }

    private static void verifySignature(String cert, String target, String sign)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IOException {
        // load cert
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(new File(cert));
        X509Certificate x509 = (X509Certificate)certFactory.generateCertificate(fis);

        // verify signature
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(x509);
        verifier.update(Files.readAllBytes(Paths.get(target)));
        if (verifier.verify(Files.readAllBytes(Paths.get(sign)))) {
            System.out.println("Signature verification SUCCESS.");
        } else {
            System.out.println("Signature verification FAILURE.");
        }
    }

    private static void generateSignature(String privKeyFile, String targetFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
            SignatureException, InvalidKeyException {

        // load priv key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        String privKeyString = Files.readString(Paths.get(privKeyFile));
        privKeyString = privKeyString.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyString = privKeyString.replace("-----END PRIVATE KEY-----", "");
        privKeyString = privKeyString.replaceAll(System.lineSeparator(), "");

        byte[] privKeyBytes = Base64.getDecoder().decode(privKeyString);

        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(privKeyBytes);
        PrivateKey privKey = keyFactory.generatePrivate(kspec);

        // generate signature
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privKey);
        signer.update(Files.readAllBytes(Paths.get(targetFile)));
        byte[] signBytes = signer.sign();

        // output signature
        writeFile(signBytes, targetFile + ".sign");
    }

    private static boolean writeFile(byte[] data, String fileName) throws IOException {
        File output = new File(fileName);
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(data);
        fos.close();
        return true;
    }

    private static void printHowToUse() {
        System.out.println("* How to Use\n" +
                "java RsaSignVeriChain sign [privKey] [target]\n" +
                "java RsaSignVeriChain verify [x509] [target] [signature]\n" +
                "java RsaSignVeriChain chain [targetCert] [issuerCert]\n");
        System.exit(0);
    }
}
