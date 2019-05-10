package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.client.ClientSession;

public interface MethodFactory {

  /**
   * @return create a new method instance
   */
  Method create(ClientSession session);
}
