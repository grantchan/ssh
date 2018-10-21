package io.github.grantchan.ssh.userauth;

import io.github.grantchan.ssh.util.KeyComparator;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;

public class PublicKeyAuth {

  private final Collection<PublicKey> keys;

  public PublicKeyAuth(Collection<PublicKey> keys) {
    this.keys = (keys == null) ? Collections.emptyList() : keys;
  }

  public boolean authenticate(PublicKey key) {
    if (key == null || keys.size() == 0) {
      return false;
    }

    for (PublicKey k : keys) {
      if (KeyComparator.compare(k, key)) {
        return true;
      }
    }

    return false;
  }
}
