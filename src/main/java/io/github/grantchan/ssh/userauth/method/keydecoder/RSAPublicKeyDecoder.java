package io.github.grantchan.ssh.userauth.method.keydecoder;

import io.github.grantchan.ssh.util.StreamUtil;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class RSAPublicKeyDecoder implements PublicKeyDecoder<RSAPublicKey> {

  private static final List<String> supportKeyTypes = Collections.singletonList("ssh-rsa");

  private static final RSAPublicKeyDecoder instance = new RSAPublicKeyDecoder();
  public static PublicKeyDecoder<?> getInstance() {
    return instance;
  }

  @Override
  public Collection<String> supportKeyTypes() {
    return supportKeyTypes;
  }

  @Override
  public RSAPublicKey decode0(InputStream key) throws IOException, GeneralSecurityException {

    BigInteger e = StreamUtil.readMpInt(key);
    BigInteger n = StreamUtil.readMpInt(key);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    return RSAPublicKey.class.cast(kf.generatePublic(new RSAPublicKeySpec(n, e)));
  }
}
