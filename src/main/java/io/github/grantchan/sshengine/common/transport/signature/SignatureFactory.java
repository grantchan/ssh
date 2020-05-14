package io.github.grantchan.sshengine.common.transport.signature;

import java.security.Key;

/**
 * An interface used to create {@link Signature} objects.
 */
public interface SignatureFactory {

  /**
   * @return create a new {@code Signature} instance
   * @see Signature
   */
  Signature create(Key key);
}
