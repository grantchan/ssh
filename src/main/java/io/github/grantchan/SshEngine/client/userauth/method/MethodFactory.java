package io.github.grantchan.SshEngine.client.userauth.method;

import io.github.grantchan.SshEngine.client.ClientSession;

public interface MethodFactory {

  /**
   * @return create a new method instance
   */
  Method create(ClientSession session);
}
