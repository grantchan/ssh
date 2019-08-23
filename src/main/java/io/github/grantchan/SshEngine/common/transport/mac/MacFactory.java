package io.github.grantchan.SshEngine.common.transport.mac;

import javax.crypto.Mac;

public interface MacFactory {

  /**
   * @return create a new MAC instance
   */
  Mac create(byte[] key);
}
