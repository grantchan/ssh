package io.github.grantchan.sshengine.client.userauth.method;

import io.github.grantchan.sshengine.client.ClientSession;

public interface MethodFactory {

  /**
   * @return create a new method instance
   */
  Method create(ClientSession session);
}
