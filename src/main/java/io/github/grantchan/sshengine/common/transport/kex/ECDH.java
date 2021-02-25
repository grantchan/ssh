package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.SshException;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.Objects;

public class ECDH extends Kex {

  private final ECParameterSpec spec;

  public ECDH(final ECurve curve) throws SshException {
    this(Objects.requireNonNull(curve).value());
  }

  public ECDH(final ECParameterSpec spec) throws SshException {
    Objects.requireNonNull(spec);

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new SshException("Failed to create EC key pair generator instance", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new SshException("Failed to initialize EC key pair generator", e);
    }

    this.spec = spec;

    KeyPair kp = kpg.generateKeyPair();
    ECPoint pt = ((ECPublicKey)kp.getPublic()).getW();
    this.pubKey = new BigInteger(ECurve.bytesOf(pt, spec.getCurve()));

    try {
      this.ka = KeyAgreement.getInstance("ECDH");
      this.ka.init(kp.getPrivate());
    } catch (NoSuchAlgorithmException e) {
      throw new SshException("Failed to create EC Diffie-Hellman key agreement instance", e);
    } catch (InvalidKeyException e) {
      throw new SshException("Failed to initialize key agreement instance", e);
    }
  }

  @Override
  public String getName() {
    return "EC";
  }

  @Override
  KeySpec getKeySpec() {
    return new ECPublicKeySpec(ECurve.ecPointOf(receivedPubKey), spec);
  }

}
