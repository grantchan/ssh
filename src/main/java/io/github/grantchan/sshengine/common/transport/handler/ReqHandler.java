package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.Service;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.kex.KexGroup;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Objects;

public interface ReqHandler extends SessionHolder, Service {

  Logger logger = LoggerFactory.getLogger(ReqHandler.class);

  // The numbers 30-49 are key exchange specific and may be redefined by other kex methods.
  byte SSH_MSG_KEXDH_FIRST = 30;
  byte SSH_MSG_KEXDH_LAST  = 49;

  KexGroup getKexGroup();

  @Override
  default void handle(int cmd, ByteBuf req) throws Exception {
    AbstractSession session = getSession();

    logger.debug("{} Handling message - {} ...", session, SshMessage.from(cmd));

    switch (cmd) {
      case SshMessage.SSH_MSG_DISCONNECT:
        handleDisconnect(req);
        break;

      case SshMessage.SSH_MSG_IGNORE:
      case SshMessage.SSH_MSG_UNIMPLEMENTED:
      case SshMessage.SSH_MSG_DEBUG:
        // ignore
        break;

      case SshMessage.SSH_MSG_KEXINIT:
        handleKexInit(req);
        break;

      case SshMessage.SSH_MSG_SERVICE_REQUEST:
        handleServiceRequest(req);
        break;

      case SshMessage.SSH_MSG_SERVICE_ACCEPT:
        handleServiceAccept(req);
        break;

      case SshMessage.SSH_MSG_NEWKEYS:
        handleNewKeys(req);
        break;

      default:
        if (cmd >= SSH_MSG_KEXDH_FIRST && cmd <= SSH_MSG_KEXDH_LAST) {
          Objects.requireNonNull(getKexGroup(), "Kex handler is not initialized").handle(cmd, req);
        } else {
          Service svc = Objects.requireNonNull(session, "Session is not initialized").getService();
          if (svc != null) {
            svc.handle(cmd, req);
          } else {
            throw new IllegalStateException("Unknown request command - " + SshMessage.from(cmd));
          }
        }
    }
  }

  void handleDisconnect(ByteBuf req) throws Exception;

  void handleKexInit(ByteBuf msg) throws Exception;

  void handleServiceRequest(ByteBuf req) throws SshException;

  void handleServiceAccept(ByteBuf req) throws SshException;

  void handleNewKeys(ByteBuf req) throws SshException;

  /**
   * Negotiates the
   * <ul><li>key exchange method,</li>
   *     <li>public key algorithm,</li>
   *     <li>symmetric encryption algorithm,</li>
   *     <li>message authentication algorithm,</li>
   *     <li>hash algorithm</li></ul>
   * supported by both parties.
   *
   * <p>
   * It iterates over client's kex algorithms, on at a time, choose the first
   * algorithm that the server also supports.
   * </p>
   *
   * @param c2s kex algorithms sent by client
   * @param s2c kex algorithms sent by server
   * @return the negotiated result, if failed, returns null
   */
  static String negotiate(String c2s, String s2c) {
    String[] c = c2s.split(",");
    String[] s = s2c.split(",");

    for (String ci : c) {
      for (String si : s) {
        if (ci.equals(si)) {
          return ci;
        }
      }
    }
    return null;
  }

  static byte[] hashKey(byte[] e, int blockSize, BigInteger k, byte[] id, MessageDigest md) {
    while (e.length < blockSize) {
      byte[] b = Bytes.concat(Bytes.addLen(k), id, e);

      md.update(b);
      e = Bytes.concat(e, md.digest());
    }

    return e;
  }

}
