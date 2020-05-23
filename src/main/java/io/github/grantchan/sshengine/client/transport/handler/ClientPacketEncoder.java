package io.github.grantchan.sshengine.client.transport.handler;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketEncoder;

import java.util.Objects;

public class ClientPacketEncoder extends AbstractPacketEncoder {

  private final ClientSession session;

  public ClientPacketEncoder(ClientSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }
}