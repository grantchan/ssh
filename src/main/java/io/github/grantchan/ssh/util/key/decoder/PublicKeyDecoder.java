package io.github.grantchan.ssh.util.key.decoder;

import io.github.grantchan.ssh.util.iostream.Reader;
import io.netty.util.internal.StringUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.stream.Collectors;

public interface PublicKeyDecoder<T extends PublicKey> {

  Collection<String> supportKeyTypes();

  default T decode(byte[] key) throws IOException, GeneralSecurityException {
    try (InputStream stream = new ByteArrayInputStream(key)) {
      return decode(stream);
    }
  }

  default T decode(InputStream key) throws IOException, GeneralSecurityException {
    String type = Reader.readLengthUtf8(key);
    if (StringUtil.isNullOrEmpty(type)) {
      throw new StreamCorruptedException("Incomplete key record - key type is missing");
    }

    Collection<String> types = supportKeyTypes();
    if (!types.contains(type)) {
      throw new InvalidKeySpecException("Invalid key type: " + type + ", expected: " +
          types.stream().collect(Collectors.joining(",")));
    }

    return decode0(key);
  }

  T decode0(InputStream key) throws IOException, GeneralSecurityException;
}
