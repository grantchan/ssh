package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.trans.signature.Signature;
import io.github.grantchan.ssh.util.KeyComparator;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class PublicKeyAuth implements Method {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Collection<PublicKey> keys;

  public PublicKeyAuth(Collection<PublicKey> keys) {
    this.keys = (keys == null) ? Collections.emptyList() : keys;
  }

  @Override
  public boolean authenticate(String user, String service, ByteBuf buf, Session session) throws Exception {
    /*
     * byte      SSH_MSG_USERAUTH_REQUEST
     * ....      fields already consumed before getting here
     * boolean   FALSE
     * string    public key algorithm name
     * string    public key blob
     */
    boolean hasSig = buf.readBoolean();
    String algorithm = SshIoUtil.readUtf8(buf);

    // save the start position of blob
    int blobPos = buf.readerIndex();
    int blobLen = buf.readInt();

    // read public key from blob
    PublicKey publicKey = SshIoUtil.readPublicKey(buf);

    boolean match = false;
    for (PublicKey key : keys) {
      if (KeyComparator.compare(key, publicKey)) {
        match = true;
      }
    }

    String remoteAddr = session.getRemoteAddress();
    if (!match) {
      logger.debug("[{}@{}] Public key not found in server - '{}'", user, remoteAddr, publicKey);

      return false;
    }

    if (!hasSig) {
      byte[] blob = new byte[blobLen + 4];
      buf.getBytes(blobPos, blob);

      session.replyUserAuthPkOk(algorithm, blob);

      throw new SshAuthInProgressException("Authentication is in progress... user: " + user + ", algorithm: "
          + algorithm);
    }

    Signature verifier = Objects.requireNonNull(BuiltinSignatureFactory.create(algorithm, publicKey));

    ByteBuf b = session.createBuffer();
    SshIoUtil.writeBytes(b, session.getId());
    b.writeByte(SshMessage.SSH_MSG_USERAUTH_REQUEST);
    SshIoUtil.writeUtf8(b, user);
    SshIoUtil.writeUtf8(b, service);
    SshIoUtil.writeUtf8(b, "publickey");
    b.writeBoolean(true);
    SshIoUtil.writeUtf8(b, algorithm);
    b.writeBytes(buf, blobPos, 4 + blobLen);

    //verifier.update(b.nioBuffer());

    return false;
  }
}
