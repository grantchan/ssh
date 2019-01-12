package io.github.grantchan.ssh.common.transport.kex;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.server.transport.kex.KexHandler;

public interface KexHandlerFactory {

  /**
   * @return create a new KexHandler instance
   */
   KexHandler create(Session session);
}
