package io.github.grantchan.ssh.userauth.handler;

import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Service;
import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;

  public UserAuthService(Session session) {
    this.session = session;
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
      String username = SshIoUtil.readUtf8(req);
      String service = SshIoUtil.readUtf8(req);
      String method = SshIoUtil.readUtf8(req);

      logger.debug("Received SSH_MSG_USERAUTH_REQUEST username={}, service={}, method={}",
                   username, service, method);
    }
  }
}
