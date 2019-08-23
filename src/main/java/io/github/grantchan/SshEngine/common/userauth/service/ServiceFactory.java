package io.github.grantchan.SshEngine.common.userauth.service;

import io.github.grantchan.SshEngine.common.Service;
import io.github.grantchan.SshEngine.common.Session;

public interface ServiceFactory {

  /**
   * @return create a new Service instance
   */
  Service create(Session session);
}
