package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CRequestHandler extends RequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  CRequestHandler(Session session) {
    super(session);
  }

  protected void handleServiceAccept(ByteBuf req) {
    String service = ByteBufIo.readUtf8(req);
    logger.debug("[{}@{}] Service: {}", session.getUsername(), session.getRemoteAddress(), service);
  }

  protected void handleNewKeys(ByteBuf req) throws SshException {
    super.handleNewKeys(req);

    session.requestServiceRequest();
  }
}
