package io.github.grantchan.SshEngine.common.transport.kex;

import io.github.grantchan.SshEngine.common.Session;

public interface KexHandlerFactory {

  /**
   * @return create a new KexHandler instance
   */
   KexHandler create(Session session);
}
