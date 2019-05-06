package io.github.grantchan.ssh.client;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.github.grantchan.ssh.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;

public class ClientSession extends Session {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public ClientSession(ChannelHandlerContext ctx) {
    super(ctx, false);
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_KEXDH_INIT} message to the server
   * @param e the public key generated by client, e = g ^ x mod p, where x is the client's private
   *          key.
   */
  @Override
  public void requestKexDhInit(BigInteger e) {
    ByteBuf req = createMessage(SshMessage.SSH_MSG_KEXDH_INIT);

    ByteBufIo.writeMpInt(req, e);

    logger.debug("[{}] Requesting SSH_MSG_KEXDH_INIT...", this);

    ctx.channel().writeAndFlush(req);
  }

  /**
   * Sends the {@link SshMessage#SSH_MSG_SERVICE_REQUEST} message to the server
   */
  @Override
  public void requestServiceRequest() {
    ByteBuf req = createMessage(SshMessage.SSH_MSG_SERVICE_REQUEST);

    ByteBufIo.writeUtf8(req, "ssh-userauth");

    logger.debug("[{}] Requesting SSH_MSG_SERVICE_REQUEST...", this);

    ctx.channel().writeAndFlush(req);
  }

  @Override
  public void requestUserAuthRequest(String user, String service, String method) {
    ByteBuf req = createMessage(SshMessage.SSH_MSG_USERAUTH_REQUEST);

    ByteBufIo.writeUtf8(req, user);
    ByteBufIo.writeUtf8(req, service);
    ByteBufIo.writeUtf8(req, method);

    logger.debug("[{}] Requesting SSH_MSG_USERAUTH_REQUEST... username:{}, service:{}, method:{}",
        this, user, service, method);

    ctx.channel().writeAndFlush(req);
  }

  @Override
  public void requestUserAuthRequest(String user, String service, String method, String algo,
                                     PublicKey pubKey) throws IOException {
    ByteBuf req = createMessage(SshMessage.SSH_MSG_USERAUTH_REQUEST);

    ByteBufIo.writeUtf8(req, user);
    ByteBufIo.writeUtf8(req, service);
    ByteBufIo.writeUtf8(req, method);
    req.writeBoolean(false);
    ByteBufIo.writeUtf8(req, algo);
    ByteBufIo.writePublicKey(req, pubKey);

    logger.debug("[{}] Requesting SSH_MSG_USERAUTH_REQUEST... " +
        "username:{}, service:{}, method:{}, algo:{}", this, user, service, method, algo);

    ctx.channel().writeAndFlush(req);
  }

  @Override
  public void requestUserAuthRequest(String user, String service, String method, String algo,
                                     PublicKey pubKey, byte[] sig) throws IOException {
    ByteBuf req = createMessage(SshMessage.SSH_MSG_USERAUTH_REQUEST);

    ByteBufIo.writeUtf8(req, user);
    ByteBufIo.writeUtf8(req, service);
    ByteBufIo.writeUtf8(req, method);
    req.writeBoolean(true);
    ByteBufIo.writeUtf8(req, algo);
    ByteBufIo.writePublicKey(req, pubKey);
    ByteBufIo.writeBytes(req, sig);

    logger.debug("[{}] Requesting SSH_MSG_USERAUTH_REQUEST... " +
            "username:{}, service:{}, method:{}, algo:{}, sigature: {}", this, user, service, method, algo,
        Bytes.md5(sig));

    ctx.channel().writeAndFlush(req);
  }
}
