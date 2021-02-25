package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.SshException;

/**
 * An interface used to create {@link KexGroup} objects.
 */
public interface KexGroupFactory {

  /**
   * @return create a new {@code KexGroup} instance
   * @see KexGroup
   */
   KexGroup create(AbstractSession session) throws SshException;
}
