package io.github.grantchan.ssh.userauth.method.keydecoder;

import io.github.grantchan.ssh.util.StreamUtil;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class DSAPublicKeyDecoder implements PublicKeyDecoder<DSAPublicKey> {

  private static final List<String> supportKeyTypes = Collections.singletonList("ssh-dss");

  private static final DSAPublicKeyDecoder instance = new DSAPublicKeyDecoder();
  public static PublicKeyDecoder<?> getInstance() {
    return instance;
  }

  @Override
  public Collection<String> supportKeyTypes() {
    return supportKeyTypes;
  }

  @Override
  public DSAPublicKey decode0(InputStream key) throws IOException, GeneralSecurityException {
    BigInteger p = StreamUtil.readMpInt(key);
    BigInteger q = StreamUtil.readMpInt(key);
    BigInteger g = StreamUtil.readMpInt(key);
    BigInteger y = StreamUtil.readMpInt(key);

    KeyFactory kf = KeyFactory.getInstance("DSA");
    return DSAPublicKey.class.cast(kf.generatePublic(new DSAPublicKeySpec(y, p, q, g)));
  }
}
