package io.github.grantchan.SshEngine.common.transport.cipher;

import javax.crypto.Cipher;

public interface CipherFactory {

  /**
   * @return create a new cipher instance
   */
  Cipher create(byte[] key, byte[] iv, int mode);
}
