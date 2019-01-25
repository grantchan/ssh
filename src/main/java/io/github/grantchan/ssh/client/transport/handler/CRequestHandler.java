package io.github.grantchan.ssh.client.transport.handler;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class CRequestHandler extends RequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public CRequestHandler(Session session) {
    super(session);
  }

  @Override
  protected void handleKexInit(ByteBuf msg) throws IOException {
    super.handleKexInit(msg);

    // if successfully handle kexinit above, should send SSH_MSG_KEXDH_INIT
  }
}
