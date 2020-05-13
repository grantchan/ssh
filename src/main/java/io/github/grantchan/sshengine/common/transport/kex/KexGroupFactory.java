package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.AbstractSession;

public interface KexGroupFactory {

  /**
   * @return create a new KexGroup instance
   */
   KexGroup create(AbstractSession session);
}
