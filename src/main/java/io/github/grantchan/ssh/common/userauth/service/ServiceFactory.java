package io.github.grantchan.ssh.common.userauth.service;

import io.github.grantchan.ssh.common.Session;

public interface ServiceFactory {

  /**
   * @return create a new Service instance
   */
  Service create(Session session);
}
