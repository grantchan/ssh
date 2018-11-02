package io.github.grantchan.ssh.userauth.handler;

import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.userauth.method.BuiltinMethodFactory;
import io.github.grantchan.ssh.userauth.method.Method;
import io.github.grantchan.ssh.userauth.service.BuiltinServiceFactory;
import io.github.grantchan.ssh.userauth.service.ServiceFactory;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;
  private String user, service, method;
  private int retryCnt, maxRetryCnt;
  private Method auth;

  public UserAuthService(Session session) {
    this.session = session;
    this.retryCnt = 0;
    this.maxRetryCnt = 10;
  }

  @Override
  public void handleMessage(int cmd, ByteBuf req) {
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
      String user = SshIoUtil.readUtf8(req);
      String service = SshIoUtil.readUtf8(req);
      String method = SshIoUtil.readUtf8(req);

      String remoteAddr = session.getRemoteAddress();

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
        logger.debug("Unsupported service - '{}', requested by '{}'", service, remoteAddr);
        session.disconnect(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                           "Unknown service - '" + service + "'");
        return;
      }

      logger.debug("Received SSH_MSG_USERAUTH_REQUEST from {} - user={}, service={}, method={}",
                   remoteAddr, user, service, method);

      if (this.user == null || this.service == null) {
        this.user = user;
        this.service = service;
      } else if (this.user.equals(user) && this.service.equals(service)) {
        retryCnt++;
        if (retryCnt >= maxRetryCnt) {
          logger.debug("Received too many login attemps - '{}' from '{}'", retryCnt, remoteAddr);
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
        logger.debug("Different user names or service names from '{}' in one authentication session",
            remoteAddr);
        session.disconnect(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR,
            "It's not allowed to change user name or service in one authentication session");
        return;
      }

      this.method = method;

      logger.debug("Authenticating user '{}' with service '{}' and method '{}' (attempt {} / {})",
          user, service, method, retryCnt, maxRetryCnt);

      auth = BuiltinMethodFactory.create(method);

      boolean result = false;
      if (auth == null) {
        logger.debug("Unsupported authentication method - '{}'", method);
      } else {
        try {
          result = auth.authenticate(user, service, req);
        } catch (Exception e) {
          logger.debug("Failed to authenticate user - '{}' by using method - '{}'", user, method);
        }
      }

      if (result) {
        session.replyUserAuthSuccess();
      } else {
        session.replyUserAuthFailure(BuiltinMethodFactory.getNames(), false);
      }
      auth = null;
    }
  }
}
