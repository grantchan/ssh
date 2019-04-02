package io.github.grantchan.ssh.util.key.deserializer;

import io.github.grantchan.ssh.util.AsnSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

public class RSAKeyPairDeserializer implements KeyPairDeserializer {

  private static final String BEGIN_LINE = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String END_LINE = "-----END RSA PRIVATE KEY-----";

  private static final RSAKeyPairDeserializer instance = new RSAKeyPairDeserializer();

  public static KeyPairDeserializer getInstance() {
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

  @Override
  public KeyPair unmarshal(byte[] bytes) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(bytes);

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
    AsnSequence seq = new AsnSequence(bytes);

    BigInteger version = seq.readInteger();
    if (!version.equals(BigInteger.ZERO)) {
      /*
       * version is the version number, for compatibility with future
       * revisions of this document.  It shall be 0 for this version of the
       * document, unless multi-prime is used, in which case it shall be 1.
       */
      throw new InvalidParameterException("Invalid ASN.1 version");
    }

    BigInteger n = seq.readInteger();  // the RSA modulus n
    BigInteger e = seq.readInteger();  // the RSA public exponent e
    BigInteger d = seq.readInteger();  // the RSA private exponent d
    BigInteger p = seq.readInteger();  // the prime factor p of n
    BigInteger q = seq.readInteger();  // the prime factor q of n
    BigInteger dp = seq.readInteger(); // d mod (p - 1)
    BigInteger dq = seq.readInteger(); // d mod (q - 1)
    BigInteger c = seq.readInteger();  // the CRT coefficient q^(-1) mod p

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(n, e));
    PrivateKey priKey = kf.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, c));

    return new KeyPair(pubKey, priKey);
  }
}
