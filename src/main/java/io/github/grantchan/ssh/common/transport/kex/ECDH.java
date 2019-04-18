package io.github.grantchan.ssh.common.transport.kex;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.Objects;

public class ECDH extends KeyExchange {

  private ECParameterSpec spec;

  public ECDH(final ECurve curve) {
    this(Objects.requireNonNull(curve).value());
  }

  public ECDH(final ECParameterSpec spec) {
    Objects.requireNonNull(spec);

    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(spec);
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return;
    }

    this.spec = spec;

    KeyPair kp = kpg.generateKeyPair();
    ECPoint pt = ((ECPublicKey)kp.getPublic()).getW();
    this.pubKey = ECurve.bytesOf(pt, spec.getCurve());

    try {
      this.ka = KeyAgreement.getInstance("ECDH");
      this.ka.init(kp.getPrivate());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
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
