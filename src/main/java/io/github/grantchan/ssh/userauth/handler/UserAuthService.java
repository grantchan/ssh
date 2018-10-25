package io.github.grantchan.ssh.userauth.handler;

import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.userauth.method.BuiltinMethodFactory;
import io.github.grantchan.ssh.userauth.method.Method;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

public class UserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;
  private String user, service, method;
  private int retryCnt, maxRetryCnt;
  private Method auth;

  public UserAuthService(Session session) {
    this.session = session;
    this.retryCnt = 0;
    this.maxRetryCnt = 20;
  }

  @Override
  public void handleMessage(ChannelHandlerContext ctx, int cmd, ByteBuf req) {
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

      InetSocketAddress peerAddr = (InetSocketAddress) ctx.channel().remoteAddress();
      logger.debug("Received SSH_MSG_USERAUTH_REQUEST from {} - user={}, service={}, method={}",
                   peerAddr.getAddress(), user, service, method);

      if (this.user == null || this.service == null) {
        this.user = user;
        this.service = service;
      } else if (this.user.equals(user) && this.service.equals(service)) {
        retryCnt++;
        if (retryCnt >= maxRetryCnt) {
          // Too many attempts, disconnect

          return;
        }
      } else {
          // It's not allowed to change user name or service name within a connection, disconnect

        return;
      }

      this.method = method;

      logger.debug("Authenticating user '{}' with service '{}' and method '{}' (attempt {} / {})",
          user, service, method, retryCnt, maxRetryCnt);

      auth = BuiltinMethodFactory.create(method);
      if (auth == null) {
        // Log error - unsupported authentication method
        // disconnect

        return;
      }

      try {
        auth.authenticate(user, service, req);
      } catch (Exception e) {
        // Log error, failed to authenticate
      }
    }
  }
}
