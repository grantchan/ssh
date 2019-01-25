package io.github.grantchan.ssh.server.transport.handler;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.handler.RequestHandler;
import io.github.grantchan.ssh.util.buffer.SshByteBuf;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SRequestHandler extends RequestHandler {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public SRequestHandler(Session session) {
    super(session);
  }

  protected void handleServiceRequest(ByteBuf req) {
    /*
     * RFC 4253:
     * The client sends SSH_MSG_SERVICE_REQUEST:
     *   byte      SSH_MSG_SERVICE_REQUEST
     *   string    service name
     *
     * After the key exchange, the client requests a service.  The service
     * is identified by a name.  The format of names and procedures for
     * defining new names are defined in [SSH-ARCH] and [SSH-NUMBERS].
     *
     * Currently, the following names have been reserved:
     *
     *    ssh-userauth
     *    ssh-connection
     *
     * Similar local naming policy is applied to the service names, as is
     * applied to the algorithm names.  A local service should use the
     * PRIVATE USE syntax of "servicename@domain".
     *
     * If the server rejects the service request, it SHOULD send an
     * appropriate SSH_MSG_DISCONNECT message and MUST disconnect.
     *
     * When the service starts, it may have access to the session identifier
     * generated during the key exchange.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-10">Service Request</a>
     */
    String svcName = SshByteBuf.readUtf8(req);
    logger.info(svcName);

    try {
      session.acceptService(svcName);
    } catch (Exception e) {
      logger.info("Requested service ({}) from {} is unavailable, rejected.",
          svcName, session.getRemoteAddress());

      // disconnect
      session.disconnect(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
          "Bad service requested - '" + svcName + "'");
      return;
    }
    session.replyAccept(svcName);

    // send welcome banner
  }
}