package io.github.grantchan.ssh.userauth.method;

import java.io.File;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Objects;

public class FileBasedPublicKeyAuth extends PublicKeyAuth {

  public FileBasedPublicKeyAuth(File authorizedKeysFile) {
    super(deserializeKeys(authorizedKeysFile));
  }

  private static Collection<PublicKey> deserializeKeys(File authorizedKeysFile) {
    Objects.requireNonNull(authorizedKeysFile);

    return null;
  }
}
