package io.github.grantchan.SshEngine.common.connection;

import io.github.grantchan.SshEngine.common.Session;

public interface ChannelFactory {

  /**
   * @return a new Channel instance
   */
  Channel create(Session session);
}
