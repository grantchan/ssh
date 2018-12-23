package io.github.grantchan.ssh.trans.kex;

import io.github.grantchan.ssh.common.Session;

public interface KexHandlerFactory {

  /**
   * @return create a new KexHandler instance
   */
   KexHandler create(Session session);
}
