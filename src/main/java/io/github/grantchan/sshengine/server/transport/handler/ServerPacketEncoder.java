package io.github.grantchan.sshengine.server.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketEncoder;
import io.github.grantchan.sshengine.server.ServerSession;

import java.util.Objects;

public class ServerPacketEncoder extends AbstractPacketEncoder {

  private final ServerSession session;

  public ServerPacketEncoder(ServerSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }
}