package io.github.grantchan.ssh.factory;

import javax.crypto.Mac;

public interface MacFactory {

  /**
   * @return create a new MAC instance
   */
  Mac create(byte[] key);
}
