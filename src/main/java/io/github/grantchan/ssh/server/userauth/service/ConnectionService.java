package io.github.grantchan.ssh.server.userauth.service;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectionService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Session session;

  public ConnectionService(Session session) {
    this.session = session;
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) throws Exception {

  }
}
