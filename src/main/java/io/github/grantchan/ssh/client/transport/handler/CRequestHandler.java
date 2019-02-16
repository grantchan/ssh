package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.netty.buffer.ByteBuf;

public class CRequestHandler extends RequestHandler {

  CRequestHandler(Session session) {
    super(session);
  }

  protected void handleNewKeys(ByteBuf req) throws SshException {
    super.handleNewKeys(req);

    session.requestServiceRequest();
  }
}
