package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.SshException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Objects;

public class DH extends Kex {

  private final BigInteger p; // safe prime;
  private final BigInteger g; // generator for subgroup

  public DH(final DhGroup dhg) throws SshException {
    this(Objects.requireNonNull(dhg).P(), dhg.G());
  }

  public DH(final BigInteger p, final BigInteger g) throws SshException {
    this.p = Objects.requireNonNull(p);
    this.g = Objects.requireNonNull(g);

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("DH");
      DHParameterSpec spec = new DHParameterSpec(p, g);
      kpg.initialize(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new SshException("Failed to create the Diffie-Hellman key pair generator instance", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new SshException("Failed to initialize the key pair generator", e);
    }

    KeyPair kp = kpg.generateKeyPair();
    this.pubKey = ((DHPublicKey)kp.getPublic()).getY();

    try {
      this.ka = KeyAgreement.getInstance("DH");
      this.ka.init(kp.getPrivate());
    } catch (NoSuchAlgorithmException e) {
      throw new SshException("Failed to create the Diffie-Hellman key agreement instance", e);
    } catch (InvalidKeyException e) {
      throw new SshException("Failed to initialize the key agreeement", e);
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
