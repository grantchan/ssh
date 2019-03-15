package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;

public interface MethodFactory {

  /**
   * @return create a new method instance
   */
  Method create(Session session);
}
