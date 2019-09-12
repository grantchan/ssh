package io.github.grantchan.SshEngine.server.userauth.service;

import io.github.grantchan.SshEngine.arch.SshMessage;
import io.github.grantchan.SshEngine.common.AbstractLogger;
import io.github.grantchan.SshEngine.common.Service;
import io.github.grantchan.SshEngine.common.SshException;
import io.github.grantchan.SshEngine.common.userauth.service.ServiceFactories;
import io.github.grantchan.SshEngine.common.userauth.service.ServiceFactory;
import io.github.grantchan.SshEngine.server.ServerSession;
import io.github.grantchan.SshEngine.server.userauth.method.Method;
import io.github.grantchan.SshEngine.server.userauth.method.MethodFactories;
import io.github.grantchan.SshEngine.server.userauth.method.SshAuthInProgressException;
import io.github.grantchan.SshEngine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerUserAuthService extends AbstractLogger
                                   implements Service {

  private ServerSession session;
  private String service;
  private int retryCnt, maxRetryCnt;

  public ServerUserAuthService(ServerSession session) {
    this.session = session;
    this.retryCnt = 0;
    this.maxRetryCnt = 10;
  }

  @Override
  public void handle(int cmd, ByteBuf req) throws Exception {
    if (cmd == SshMessage.SSH_MSG_USERAUTH_REQUEST) {

      /*
       * byte      SSH_MSG_USERAUTH_REQUEST
       * string    user name in ISO-10646 UTF-8 encoding [RFC3629]
       * string    service name in US-ASCII
       * string    method name in US-ASCII
       * ....      method specific fields
       *
       * @see <a href="https://tools.ietf.org/html/rfc4252#section-5">Authentication Requests</a>
       */
      String user = ByteBufIo.readUtf8(req);
      String service = ByteBufIo.readUtf8(req);
      String method = ByteBufIo.readUtf8(req);

      logger.debug("[{}] Received SSH_MSG_USERAUTH_REQUEST service={}, method={}",
                   session, service, method);

      /*
       * RFC 4252:
       * The 'service name' specifies the service to start after
       * authentication.  There may be several different authenticated
       * services provided.  If the requested service is not available, the
       * server MAY disconnect immediately or at any later time.  Sending a
       * proper disconnect message is RECOMMENDED.  In any case, if the
       * service does not exist, authentication MUST NOT be accepted.
       *
       * @see <a href="https://tools.ietf.org/html/rfc4252#section-5">Authentication Requests</a>
       */
      ServiceFactory factory = ServiceFactories.from(service);
      if (factory == null){
        logger.debug("[{}] Unsupported service - '{}'", session, service);

        throw new SshException(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
            "Unknown service - '" + service + "'");
      }

      if (session.getUsername() == null || this.service == null) {
        session.setUsername(user);
        this.service = service;
      } else if (session.getUsername().equals(user) && this.service.equals(service)) {
        retryCnt++;

        if (retryCnt >= maxRetryCnt) {
          logger.debug("[{}] Too many login attemps", session);

          throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
              "Too many login attempts.");
        }
      } else {
        // The 'user name' and 'service name' are repeated in every new
        // authentication attempt, and MAY change.  The server implementation
        // MUST carefully check them in every message, and MUST flush any
        // accumulated authentication states if they change.  If it is unable to
        // flush an authentication state, it MUST disconnect if the 'user name'
        // or 'service name' changes.
        logger.debug("[{}] User name or service name differs in one authentication session",
                     session);

        throw new SshException(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
            "It's not allowed to change user name or service in one authentication session");
      }

      Method auth = MethodFactories.create(method);

      boolean result = false;
      if (auth == null) {
        logger.debug("[{}] Unsupported authentication method - '{}'", session, method);
      } else {
        logger.debug("[{}] Authenticating to start service '{}' by method '{}' (attempt {} / {})",
                     session, service, method, retryCnt, maxRetryCnt);

        try {
          result = auth.authorize(user, service, req, session);
        } catch (SshAuthInProgressException e) {
          logger.debug("[{}] Authentication in progress...", session);

          return;
        } catch (Exception e) {
          logger.debug("[{}] Failed to authenticate. method={}", session, method);
        }
      }

      if (result) {
        session.acceptService(service);
        session.replyUserAuthSuccess();
        session.setAuthed(true);
      } else {
        session.replyUserAuthFailure(MethodFactories.getNames(), false);
      }
    }
  }
}
