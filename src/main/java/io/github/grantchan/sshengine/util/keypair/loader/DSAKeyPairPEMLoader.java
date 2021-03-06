package io.github.grantchan.sshengine.util.keypair.loader;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Objects;

public class DSAKeyPairPEMLoader implements KeyPairPEMLoader {

  private static final String BEGIN_LINE = "-----BEGIN DSA PRIVATE KEY-----";
  private static final String END_LINE = "-----END DSA PRIVATE KEY-----";

  private static final DSAKeyPairPEMLoader instance = new DSAKeyPairPEMLoader();

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
   * Transform the DSA key pair bytes array into {@link KeyPair}
   *
   * The bytes array is encoded by DER - A way to encode ASN.1 syntax in binary, a .pem file is just
   * a Base64 encoded .der file.
   *
   * OpenSSL can convert these to .pem:
   * openssl x509 -inform der -in to-convert.der -out converted.pem
   *
   * @param keyBytes the key pair bytes array
   * @return The {@link KeyPair} object represents the DSA key pair
   * @throws IOException if any error happens when reading the array
   * @throws GeneralSecurityException if key pair data in the array is invalid
   */
  @Override
  public KeyPair load(byte[] keyBytes) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(keyBytes);

    /*
     * A DSA key pair has 5 distinct components: P, Q, G, public key part, private key part.
     * Digging into the source of OpenSSL (used by OpenSSH for this) crypto/dsa/dsa_asn1.c:
     *
     * ASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = {
     *     ASN1_SIMPLE(DSA, version, LONG),
     *     ASN1_SIMPLE(DSA, p, BIGNUM),
     *     ASN1_SIMPLE(DSA, q, BIGNUM),
     *     ASN1_SIMPLE(DSA, g, BIGNUM),
     *     ASN1_SIMPLE(DSA, y, BIGNUM),
     *     ASN1_SIMPLE(DSA, x, BIGNUM)
     * } ASN1_SEQUENCE_END_cb(DSA, DSAPrivateKey)
     */

    DerInputStream dis = new DerInputStream(keyBytes);
    DerValue[] seq = dis.getSequence(0);

    BigInteger version = seq[0].getBigInteger();

    BigInteger p = seq[1].getBigInteger(); // prime number (public)
    BigInteger q = seq[2].getBigInteger(); // 160-bit subprime, q | p - 1 (public)
    BigInteger g = seq[3].getBigInteger(); // generator of subgroup (public)
    BigInteger y = seq[4].getBigInteger(); // public key: y = g^x
    BigInteger x = seq[5].getBigInteger(); // private key

    KeyFactory kf = KeyFactory.getInstance("DSA");

    PublicKey pubKey = kf.generatePublic(new DSAPublicKeySpec(y, p, q, g));
    PrivateKey prvKey = kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));

    return new KeyPair(pubKey, prvKey);
  }
}
