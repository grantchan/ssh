package io.github.grantchan.ssh.client.userauth;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.client.userauth.method.Method;
import io.github.grantchan.ssh.client.userauth.method.MethodFactories;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class ClientUserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;

  private Iterator<String> clientMethods;
  private Method auth;

  public ClientUserAuthService(Session session) {
    this.session = session;

    Collection<String> methods = new LinkedList<>(
        Arrays.asList(Objects.requireNonNull(MethodFactories.getNames()).split(",")));

    clientMethods = methods.iterator();

    if (methods.size() == 0) {
      throw new RuntimeException("No authentication method available");
    }

    logger.debug("[{}@{}] Authentication methods for client - {}",
        session.getUsername(), session.getRemoteAddress(), String.join(",", methods));
  }

  @Override
  public void handleMessage(int cmd, ByteBuf rsp) throws Exception {
    String user = session.getUsername();
    String remoteAddr = session.getRemoteAddress();

    if (cmd == SshMessage.SSH_MSG_USERAUTH_SUCCESS) {

      /*
       * Responses to Authentication Requests
       *
       * When the server accepts authentication, it MUST respond with the
       * following:
       *
       * byte      SSH_MSG_USERAUTH_SUCCESS
       *
       * Note that this is not sent after each step in a multi-method
       * authentication sequence, but only when the authentication is
       * complete.
       *
       * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.1">Responses to Authentication Requests</a>
       *
       *
       * Completion of User Authentication
       *
       * Authentication is complete when the server has responded with
       * SSH_MSG_USERAUTH_SUCCESS.  All authentication related messages
       * received after sending this message SHOULD be silently ignored.
       *
       * After sending SSH_MSG_USERAUTH_SUCCESS, the server starts the
       * requested service.
       *
       * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.3">Completion of User Authentication</a>
       */
      logger.debug("[{}@{}] User authentication succeeded.", user, remoteAddr);

      session.acceptService("ssh-connection");

      return;
    }

    String methods = ByteBufIo.readUtf8(rsp);
    List<String> serverMethods = Arrays.asList(methods.split(","));

    if (cmd == SshMessage.SSH_MSG_USERAUTH_FAILURE) {

      /*
       * If the server rejects the authentication request, it MUST respond
       * with the following:
       *
       * byte         SSH_MSG_USERAUTH_FAILURE
       * name-list    authentications that can continue
       * boolean      partial success
       *
       * The 'authentications that can continue' is a comma-separated name-
       * list of authentication 'method name' values that may productively
       * continue the authentication dialog.
       *
       * It is RECOMMENDED that servers only include those 'method name'
       * values in the name-list that are actually useful.  However, it is not
       * illegal to include 'method name' values that cannot be used to
       * authenticate the user.
       *
       * Already successfully completed authentications SHOULD NOT be included
       * in the name-list, unless they should be performed again for some
       * reason.
       *
       * The value of 'partial success' MUST be TRUE if the authentication
       * request to which this is a response was successful.  It MUST be FALSE
       * if the request was not successfully processed.
       *
       * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.1">Responses to Authentication Requests</a>
       */
      boolean partial = rsp.readBoolean();

      logger.debug("[{}@{}] Received SSH_MSG_USERAUTH_FAILURE - methods={}, partial={}",
          user, remoteAddr, methods, partial);

      if (partial) {
        logger.debug("[{}@{}] Multi-method authentication is not implemented, authentication " +
            "failed.", user, remoteAddr);

        throw new IllegalStateException("Multi-method authentication is not implemented.");
      }

      auth = null;

      nextMethod(serverMethods);

      return;
    }

    if (auth == null) {
      String msg = SshMessage.from(cmd);

      logger.debug("[] Illegal authentication response - {}", msg);

      throw new IllegalStateException("Illegal authentication response: " + msg);
    }

    if (!auth.authenticate()) {
      nextMethod(serverMethods);
    }
  }

  private void nextMethod(List<String> serverMethods) throws SshException {

    while (true) {
      if (auth == null) {
        logger.debug("About to start authentication process - methods(Client): {}, " +
            "method(Server): {}", clientMethods, serverMethods);
      } else if (!auth.submit()) {
        logger.debug("No available initial authentication request to send, trying next method");

        auth = null;
      } else {
        logger.debug("Initial authentication request is sent successfully");

        return;
      }

      while (clientMethods.hasNext()) {
        String clientMethod = clientMethods.next();
        if (serverMethods.contains(clientMethod)) {
          auth = MethodFactories.create(clientMethod, session);
          if (auth == null) {
            logger.debug("Failed to create authentication method - {}", clientMethod);

            throw new IllegalStateException("Failed to create authentication method - " +
                clientMethod);
          }
        }
      }

      if (auth == null) {
        logger.debug("No more authentication methods available");

        throw new SshException(SshMessage.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
            "No more authentication methods available");
      }
    }
  }

}
