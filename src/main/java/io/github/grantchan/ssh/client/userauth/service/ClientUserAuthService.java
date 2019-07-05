package io.github.grantchan.ssh.client.userauth.service;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.client.userauth.method.Method;
import io.github.grantchan.ssh.client.userauth.method.MethodFactories;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class ClientUserAuthService implements Service {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private ClientSession session;

  private Iterator<String> clientMethods;
  private List<String> serverMethods;
  private Method auth;

  public ClientUserAuthService(ClientSession session) {
    this.session = session;

    Collection<String> methods = new LinkedList<>(
        Arrays.asList(Objects.requireNonNull(MethodFactories.getNames()).split(",")));

    clientMethods = methods.iterator();

    if (methods.size() == 0) {
      throw new RuntimeException("No authentication method available");
    }

    logger.debug("[{}] Authentication methods for client - {}", session, String.join(",", methods));
  }

  @Override
  public void handleMessage(int cmd, ByteBuf msg) throws Exception {
    switch (cmd) {
      case SshMessage.SSH_MSG_USERAUTH_BANNER:
        handleBanner(msg);
        return;

      case SshMessage.SSH_MSG_USERAUTH_SUCCESS:
        handleSuccess();
        return;

      case SshMessage.SSH_MSG_USERAUTH_FAILURE:
        handleFailure(msg);
        return;

      case SshMessage.SSH_MSG_USERAUTH_PK_OK:
        if (auth != null) {
          handlePkOk(msg);
          return;
        }

      default:
        String rsp = SshMessage.from(cmd);

        logger.debug("[{}] Illegal authentication response - {}", session, rsp);

        throw new IllegalStateException("Illegal authentication response: " + rsp);
    }
  }

  private void handleBanner(ByteBuf msg) {
    /*
     * The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
     * time after this authentication protocol starts and before
     * authentication is successful.  This message contains text to be
     * displayed to the client user before authentication is attempted.  The
     * format is as follows:
     *
     *    byte      SSH_MSG_USERAUTH_BANNER
     *    string    message in ISO-10646 UTF-8 encoding [RFC3629]
     *    string    language tag [RFC3066]
     *
     * By default, the client SHOULD display the 'message' on the screen.
     * However, since the 'message' is likely to be sent for every login
     * attempt, and since some client software will need to open a separate
     * window for this warning, the client software may allow the user to
     * explicitly disable the display of banners from the server.  The
     * 'message' may consist of multiple lines, with line breaks indicated
     * by CRLF pairs.
     *
     * If the 'message' string is displayed, control character filtering,
     * discussed in [SSH-ARCH], SHOULD be used to avoid attacks by sending
     * terminal control characters.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4252#section-5.4">Banner Message</a>
     */
    String banner = ByteBufIo.readUtf8(msg);
    String lang = ByteBufIo.readUtf8(msg);

    logger.debug("[{}] Banner message(lang={}):", session, lang);
    logger.debug(banner);
  }

  private void handleSuccess() throws Exception {
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
    logger.debug("[{}] User authentication succeeded.", session);

    session.setAuthed(true);
    session.acceptService("ssh-connection");
  }

  private void handleFailure(ByteBuf msg) throws Exception {
    String methods = ByteBufIo.readUtf8(msg);
    serverMethods = Arrays.asList(methods.split(","));

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
    boolean partial = msg.readBoolean();

    logger.debug("[{}] Received SSH_MSG_USERAUTH_FAILURE - methods={}, partial={}",
        session, methods, partial);

    if (partial) {
      logger.debug("[{}] Multi-method authentication is not implemented, authentication " +
          "failed.", session);

      throw new IllegalStateException("Multi-method authentication is not implemented.");
    }

    auth = null;

    nextMethod();
  }

  private void handlePkOk(ByteBuf msg) throws Exception {
    if (!auth.authenticate(msg)) {
      nextMethod();
    }
  }

  private void nextMethod() throws SshException {

    while (true) {
      if (auth == null) {
        logger.debug("[{}] About to start authentication process - methods(Client): {}, " +
            "method(Server): {}", session, clientMethods, serverMethods);
      } else if (!auth.submit()) {
        logger.debug("[{}] No available initial authentication request to send, trying next method",
            session);

        auth = null;
      } else {
        logger.debug("[{}] Initial authentication request is sent successfully", session);

        return;
      }

      while (clientMethods.hasNext()) {
        String clientMethod = clientMethods.next();
        if (serverMethods.contains(clientMethod)) {
          auth = MethodFactories.create(clientMethod, session);
          if (auth == null) {
            logger.debug("[{}] Failed to create authentication method - {}", session, clientMethod);

            throw new IllegalStateException("Failed to create authentication method - " +
                clientMethod);
          }
        }
      }

      if (auth == null) {
        logger.debug("[{}] No more authentication methods available", session);

        throw new SshException(SshMessage.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
            "No more authentication methods available");
      }
    }
  }

}
