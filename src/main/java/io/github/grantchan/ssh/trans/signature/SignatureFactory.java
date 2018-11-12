package io.github.grantchan.ssh.trans.signature;

import java.security.Key;

public interface SignatureFactory {

  /**
   * @return create a new Signature instance
   */
  Signature create(Key key);

}
