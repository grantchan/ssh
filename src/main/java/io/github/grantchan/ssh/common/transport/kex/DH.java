package io.github.grantchan.ssh.common.transport.kex;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.KeySpec;
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
    this.pubKey = ((DHPublicKey)kp.getPublic()).getY();

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
  public String getName() {
    return "DH";
  }

  @Override
  KeySpec getKeySpec() {
    return new DHPublicKeySpec(this.receivedPubKey, p, g);
  }
}
