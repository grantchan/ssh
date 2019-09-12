package io.github.grantchan.sshengine.util.publickey.decoder;

import io.github.grantchan.sshengine.util.iostream.Reader;

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
  public Collection<String> supportTypes() {
    return supportKeyTypes;
  }

  @Override
  public RSAPublicKey decode0(InputStream key) throws IOException, GeneralSecurityException {
    BigInteger e = Reader.readMpInt(key);
    BigInteger n = Reader.readMpInt(key);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(n, e));
  }
}
