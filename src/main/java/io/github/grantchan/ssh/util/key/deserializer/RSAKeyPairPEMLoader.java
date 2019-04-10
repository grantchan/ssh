package io.github.grantchan.ssh.util.key.deserializer;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

public class RSAKeyPairPEMLoader implements KeyPairPEMLoader {

  private static final String BEGIN_LINE = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String END_LINE = "-----END RSA PRIVATE KEY-----";

  private static final RSAKeyPairPEMLoader instance = new RSAKeyPairPEMLoader();

  public static KeyPairPEMLoader getInstance() {
    return instance;
  }

  @Override
  public String getBeginLine() {
    return BEGIN_LINE;
  }

  @Override
  public String getEndLine() {
    return END_LINE;
  }

  /**
   * Transform the RSA key pair bytes array into {@link KeyPair}
   *
   * The bytes array is encoded by DER - A way to encode ASN.1 syntax in binary, a .pem file is just
   * a Base64 encoded .der file.
   *
   * OpenSSL can convert these to .pem:
   * openssl x509 -inform der -in to-convert.der -out converted.pem
   *
   * @param keyBytes the key pair bytes array
   * @return The {@link KeyPair} object represents the RSA key pair
   * @throws IOException if any error happens when reading the array
   * @throws GeneralSecurityException if key pair data in the array is invalid
   */
  @Override
  public KeyPair load(byte[] keyBytes) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(keyBytes);

    /*
     * An RSA private key should be represented with the ASN.1 type
     * RSAPrivateKey:
     *
     * RSAPrivateKey ::= SEQUENCE {
     *     version           Version,
     *     modulus           INTEGER,  -- n
     *     publicExponent    INTEGER,  -- e
     *     privateExponent   INTEGER,  -- d
     *     prime1            INTEGER,  -- p
     *     prime2            INTEGER,  -- q
     *     exponent1         INTEGER,  -- d mod (p-1)
     *     exponent2         INTEGER,  -- d mod (q-1)
     *     coefficient       INTEGER,  -- (inverse of q) mod p
     *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
     * }
     *
     * <a href="https://tools.ietf.org/html/rfc3447#appendix-A.1.2">A.1.2 RSA private key syntax</a>
     */

    DerInputStream dis = new DerInputStream(keyBytes);
    DerValue[] seq = dis.getSequence(0);
    
    BigInteger version = seq[0].getBigInteger();
    if (!version.equals(BigInteger.ZERO)) {
      /*
       * version is the version number, for compatibility with future
       * revisions of this document.  It shall be 0 for this version of the
       * document, unless multi-prime is used, in which case it shall be 1.
       */
      throw new InvalidParameterException("Invalid ASN.1 version");
    }

    BigInteger n  = seq[1].getBigInteger(); // the RSA modulus n
    BigInteger e  = seq[2].getBigInteger(); // the RSA public exponent e
    BigInteger d  = seq[3].getBigInteger(); // the RSA private exponent d
    BigInteger p  = seq[4].getBigInteger(); // the prime factor p of n
    BigInteger q  = seq[5].getBigInteger(); // the prime factor q of n
    BigInteger dp = seq[6].getBigInteger(); // d mod (p - 1)
    BigInteger dq = seq[7].getBigInteger(); // d mod (q - 1)
    BigInteger c  = seq[8].getBigInteger(); // the CRT coefficient q^(-1) mod p

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(n, e));
    PrivateKey prvKey = kf.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, c));

    return new KeyPair(pubKey, prvKey);
  }
}
