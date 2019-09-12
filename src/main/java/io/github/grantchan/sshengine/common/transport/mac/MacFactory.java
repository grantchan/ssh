package io.github.grantchan.sshengine.common.transport.mac;

import javax.crypto.Mac;

public interface MacFactory {

  /**
   * @return create a new MAC instance
   */
  Mac create(byte[] key);
}
