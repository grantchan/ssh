package io.github.grantchan.ssh.userauth.method.keydecoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

public interface PublicKeyDecoder<T extends PublicKey> {

  default T decode(byte[] key) throws IOException, GeneralSecurityException {
    try (InputStream stream = new ByteArrayInputStream(key)) {
      return decode(stream);
    }
  }

  T decode(InputStream key) throws IOException, GeneralSecurityException;
}
