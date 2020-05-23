package io.github.grantchan.sshengine.server.transport.handler;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketDecoder;
import io.github.grantchan.sshengine.server.ServerSession;

import java.util.Objects;

public class ServerPacketDecoder extends AbstractPacketDecoder {

  private final ServerSession session;

  public ServerPacketDecoder(ServerSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

}
