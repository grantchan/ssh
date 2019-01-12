package io.github.grantchan.ssh.userauth.service;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.userauth.service.Service;

public interface ServiceFactory {

  /**
   * @return create a new Service instance
   */
  Service create(Session session);
}
