package io.github.grantchan.ssh.userauth.method.keydecoder;

import io.github.grantchan.ssh.util.StreamUtil;
import io.netty.util.internal.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class RSAPublicKeyDecoder implements PublicKeyDecoder<RSAPublicKey> {

  private final static String KEY_TYPE = "ssh-rsa";

  @Override
  public RSAPublicKey decode(InputStream key) throws IOException, GeneralSecurityException {
    String type = StreamUtil.readLengthUtf8(key);
    if (StringUtil.isNullOrEmpty(type)) {
      throw new StreamCorruptedException("Incomplete key record - key type is missing");
    }

    if (!type.equals(KEY_TYPE)) {
      throw new InvalidKeySpecException("Invalid key type: " + type + ", expected: " + KEY_TYPE);
    }

    BigInteger e = StreamUtil.readMpInt(key);
    BigInteger n = StreamUtil.readMpInt(key);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    return RSAPublicKey.class.cast(kf.generatePublic(new RSAPublicKeySpec(n, e)));
  }
}
