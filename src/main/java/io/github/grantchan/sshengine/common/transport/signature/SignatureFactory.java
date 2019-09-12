package io.github.grantchan.sshengine.common.transport.signature;

import java.security.Key;

public interface SignatureFactory {

  /**
   * @return create a new Signature instance
   */
  Signature create(Key key);
}
