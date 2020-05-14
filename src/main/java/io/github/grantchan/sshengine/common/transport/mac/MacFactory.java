package io.github.grantchan.sshengine.common.transport.mac;

import javax.crypto.Mac;

/**
 * An interface used to create {@link Mac} objects.
 */
public interface MacFactory {

  /**
   * @return create a new {@code Mac} instance
   * @see Mac
   */
  Mac create(byte[] key);
}
