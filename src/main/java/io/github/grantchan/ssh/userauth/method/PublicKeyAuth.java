package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.util.buffer.ByteBufUtil;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.trans.signature.Signature;
import io.github.grantchan.ssh.util.key.decoder.DSAPublicKeyDecoder;
import io.github.grantchan.ssh.util.key.decoder.PublicKeyDecoder;
import io.github.grantchan.ssh.util.key.decoder.RSAPublicKeyDecoder;
import io.github.grantchan.ssh.util.key.KeyComparator;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.*;

public class PublicKeyAuth implements Method {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Collection<PublicKey> keys;

  protected static final Map<String, PublicKeyDecoder> decoders =
      new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
  static {
    registerPublicKeyDecoder(DSAPublicKeyDecoder.getInstance());
    registerPublicKeyDecoder(RSAPublicKeyDecoder.getInstance());
  }

  public static void registerPublicKeyDecoder(PublicKeyDecoder<?> decoder) {
    for (String type : decoder.supportKeyTypes()) {
      decoders.put(type, decoder);
    }
  }

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
    String algorithm = ByteBufUtil.readUtf8(buf);

    // save the start position of blob
    int blobPos = buf.readerIndex();
    int blobLen = buf.readInt();

    // read public key from blob
    PublicKey publicKey = ByteBufUtil.readPublicKey(buf);

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
    ByteBufUtil.writeBytes(b, session.getId());
    b.writeByte(SshMessage.SSH_MSG_USERAUTH_REQUEST);
    ByteBufUtil.writeUtf8(b, user);
    ByteBufUtil.writeUtf8(b, service);
    ByteBufUtil.writeUtf8(b, "publickey");
    b.writeBoolean(true);
    ByteBufUtil.writeUtf8(b, algorithm);
    b.writeBytes(buf, blobPos, 4 + blobLen);

    //verifier.update(b.nioBuffer());

    return false;
  }
}
