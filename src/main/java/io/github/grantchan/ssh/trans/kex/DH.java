package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.util.buffer.Bytes;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class DH extends KeyExchange {

  private BigInteger p; // safe prime;
  private BigInteger g; // generator for subgroup

  public DH(final DhGroup dhg) {
    this(Objects.requireNonNull(dhg).P(), dhg.G());
  }

  public DH(final BigInteger p, final BigInteger g) {
    this.p = Objects.requireNonNull(p);
    this.g = Objects.requireNonNull(g);

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("DH");
      DHParameterSpec spec = new DHParameterSpec(p, g);
      kpg.initialize(spec);
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return;
    }

    KeyPair kp = kpg.generateKeyPair();
    this.pubKey = ((DHPublicKey)kp.getPublic()).getY().toByteArray();

    try {
      this.ka = KeyAgreement.getInstance("DH");
      this.ka.init(kp.getPrivate());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }

  @Override
  public byte[] getSecretKey() {
    try {
      KeyFactory kf = KeyFactory.getInstance("DH");
      DHPublicKeySpec spec = new DHPublicKeySpec(new BigInteger(receivedPubKey), p, g);

      ka.doPhase(kf.generatePublic(spec), true);
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }

    byte[] k = Objects.requireNonNull(ka.generateSecret());

    int i = 0;
    while (k[i] == 0) {
      i++;
    }

    return Bytes.last(k, k.length - i);
  }
}
