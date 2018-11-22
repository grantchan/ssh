package io.github.grantchan.ssh.userauth.service;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.userauth.method.BuiltinMethodFactory;
import io.github.grantchan.ssh.userauth.method.Method;
import io.github.grantchan.ssh.userauth.method.SshAuthInProgressException;
import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;
  private String user, service;
  private int retryCnt, maxRetryCnt;

  public UserAuthService(Session session) {
    this.session = session;
    this.retryCnt = 0;
    this.maxRetryCnt = 10;
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) throws Exception {
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
      String user = ByteBufUtil.readUtf8(req);
      String service = ByteBufUtil.readUtf8(req);
      String method = ByteBufUtil.readUtf8(req);

      String remoteAddr = session.getRemoteAddress();

      logger.debug("[{}@{}] Received SSH_MSG_USERAUTH_REQUEST service={}, method={}",
                   user, remoteAddr, service, method);

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
      ServiceFactory factory = BuiltinServiceFactory.from(service);
      if (factory == null){
        logger.debug("[{}@{}] Unsupported service - '{}'", user, remoteAddr, service);

        session.disconnect(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                           "Unknown service - '" + service + "'");

        return;
      }

      if (this.user == null || this.service == null) {
        this.user = user;
        this.service = service;
      } else if (this.user.equals(user) && this.service.equals(service)) {
        retryCnt++;

        if (retryCnt >= maxRetryCnt) {
          logger.debug("[{}@{}] Too many login attemps", user, remoteAddr);

          session.disconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR, "Too many login attempts.");

          return;
        }
      } else {
        // The 'user name' and 'service name' are repeated in every new
        // authentication attempt, and MAY change.  The server implementation
        // MUST carefully check them in every message, and MUST flush any
        // accumulated authentication states if they change.  If it is unable to
        // flush an authentication state, it MUST disconnect if the 'user name'
        // or 'service name' changes.
        logger.debug("[{}@{}] User name or service name differs in one authentication session",
                     user, remoteAddr);

        session.disconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
            "It's not allowed to change user name or service in one authentication session");

        return;
      }

      Method auth = BuiltinMethodFactory.create(method);

      boolean result = false;
      if (auth == null) {
        logger.debug("Unsupported authentication method - '{}'", method);
      } else {
        logger.debug("[{}@{}] Authenticating to start service '{}' by method '{}' (attempt {} / {})",
                     user, remoteAddr, service, method, retryCnt, maxRetryCnt);

        try {
          result = auth.authenticate(user, service, req, session);
        } catch (SshAuthInProgressException e) {
          logger.debug("[{}@{}] Authentication in progress...", user, remoteAddr);

          return;
        } catch (Exception e) {
          logger.debug("[{}@{}] Failed to authenticate.  method={}", user, remoteAddr, method);
        }
      }

      if (result) {
        session.acceptService(service);
        session.replyUserAuthSuccess();
      } else {
        session.replyUserAuthFailure(BuiltinMethodFactory.getNames(), false);
      }
    }
  }
}
