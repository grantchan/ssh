package io.github.grantchan.sshengine.common.transport.cipher;

import io.github.grantchan.sshengine.common.SshException;

import javax.crypto.Cipher;

/**
 * An interface used to create {@link Cipher} objects.
 */
public interface CipherFactory {

  /**
   * @return create a new {@code Cipher} instance
   * @see Cipher
   */
  Cipher create(byte[] key, byte[] iv, int mode) throws SshException;
}
