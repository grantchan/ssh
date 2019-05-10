package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.SshException;
import io.github.grantchan.ssh.common.transport.kex.KexHandler;
import io.github.grantchan.ssh.common.userauth.service.Service;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.github.grantchan.ssh.util.buffer.LengthBytesBuilder;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Objects;

public interface RequestHandler {

  // The numbers 30-49 are key exchange specific and may be redefined by other kex methods.
  byte SSH_MSG_KEXDH_FIRST = 30;
  byte SSH_MSG_KEXDH_LAST  = 49;

  Session getSession();

  KexHandler getKexHandler();

  default void handle(ByteBuf req) throws Exception {
    int cmd = req.readByte() & 0xFF;

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
          Objects.requireNonNull(getKexHandler(), "Kex handler is not initialized")
                 .handleMessage(cmd, req);
        } else {
          Service svc = Objects.requireNonNull(getSession(), "Session is not initialized")
                               .getService();
          if (svc != null) {
            svc.handleMessage(cmd, req);
          } else {
            throw new IllegalStateException("Unknown request command - " + SshMessage.from(cmd));
          }
        }
    }
  }

  void handleDisconnect(ByteBuf req);

  void handleKexInit(ByteBuf msg) throws IOException;

  void handleServiceRequest(ByteBuf req) throws SshException;

  void handleServiceAccept(ByteBuf req) throws SshException;

  void handleNewKeys(ByteBuf req) throws SshException;

  /**
   * Negotiate the key exchange method, public key algorithm, symmetric encryption algorithm,
   * message authentication algorithm, and hash algorithm supported by both parties.
   *
   * It iterates over client's kex algorithms, on at a time, choose the first algorithm that the
   * server also supports.
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
      byte[] b = Bytes.concat(LengthBytesBuilder.concat(k), id, e);

      md.update(b);
      e = Bytes.concat(e, md.digest());
    }

    return e;
  }

}
