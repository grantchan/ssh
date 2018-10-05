package io.github.grantchan.ssh.factory;

import javax.crypto.Cipher;

public interface CipherFactory {

  /**
   * @return create a new cipher instance
   */
  Cipher create(byte[] key, byte[] iv, int mode);
}
