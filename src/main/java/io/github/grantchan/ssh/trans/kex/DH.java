package io.github.grantchan.ssh.trans.kex;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class DH {

  private BigInteger p; // safe prime;
  private BigInteger g; // generator for subgroup
  private BigInteger pubKey; // exchange value sent by the client
  private PrivateKey priKey;
  private byte[]     receivedPubKey; // exchange value sent by the server

  public DH(BigInteger p, BigInteger g) {
    this.p = p;
    this.g = g;

    KeyPairGenerator kpg = null;
    try {
      kpg = KeyPairGenerator.getInstance("DH");
      DHParameterSpec spec = new DHParameterSpec(p, g);
      kpg.initialize(spec);
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return;
    }

    KeyPair kp = kpg.generateKeyPair();
    pubKey = ((DHPublicKey)kp.getPublic()).getY();
    priKey = kp.getPrivate();
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }

  public byte[] getPubKey() {
    return this.pubKey.toByteArray();
  }

  public byte[] getReceivedPubKey() {
    return this.receivedPubKey;
  }

  public void receivedPubKey(byte[] key) {
    this.receivedPubKey = key;
  }

  public byte[] getSecretKey() {
    KeyAgreement ka;
    try {
      KeyFactory kf = KeyFactory.getInstance("DH");
      DHPublicKeySpec spec = new DHPublicKeySpec(new BigInteger(receivedPubKey), p, g);

      ka = KeyAgreement.getInstance("DH");
      ka.init(priKey);
      ka.doPhase(kf.generatePublic(spec), true);
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }

    byte[] x = Objects.requireNonNull(ka.generateSecret());

    int i = 0;
    while (x[i] == 0) {
      i++;
    }

    if (i == 0) {
      return x;
    }

    byte[] secretKey = new byte[x.length - i];
    System.arraycopy(x, i, secretKey, 0, secretKey.length);

    return secretKey;
  }
}
