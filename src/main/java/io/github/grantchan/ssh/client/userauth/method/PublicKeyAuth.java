package io.github.grantchan.ssh.client.userauth.method;

import java.security.KeyPair;
import java.util.Collection;

public class PublicKeyAuth implements Method {

  private Collection<KeyPair> keyPairs;

  public PublicKeyAuth(Collection<KeyPair> keyPairs) {
    this.keyPairs = keyPairs;
  }

  @Override
  public boolean submit() {
    return false;
  }
}
