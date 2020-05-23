package io.github.grantchan.sshengine.client.transport.handler;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.AbstractPacketDecoder;

import java.util.Objects;

public class ClientPacketDecoder extends AbstractPacketDecoder {

  private ClientSession session;

  ClientPacketDecoder(ClientSession session) {
    this.session = Objects.requireNonNull(session, "Session is not initialized");
  }

  @Override
  public AbstractSession getSession() {
    return this.session;
  }
}
