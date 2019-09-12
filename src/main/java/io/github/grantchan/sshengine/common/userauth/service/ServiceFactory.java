package io.github.grantchan.sshengine.common.userauth.service;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.Service;

public interface ServiceFactory {

  /**
   * @return create a new Service instance
   */
  Service create(AbstractSession session);
}
