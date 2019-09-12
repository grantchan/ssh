package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.common.AbstractSession;

public interface KexHandlerFactory {

  /**
   * @return create a new KexHandler instance
   */
   KexHandler create(AbstractSession session);
}
