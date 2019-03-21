package io.github.grantchan.ssh.server.userauth.method;

import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.common.transport.signature.Signature;
import io.github.grantchan.ssh.common.transport.signature.SignatureFactories;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.github.grantchan.ssh.util.key.Comparator;
import io.github.grantchan.ssh.util.key.decoder.DSAPublicKeyDecoder;
import io.github.grantchan.ssh.util.key.decoder.PublicKeyDecoder;
import io.github.grantchan.ssh.util.key.decoder.RSAPublicKeyDecoder;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class PublicKeyAuth implements Method {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final Collection<PublicKey> keys;

  static final Map<String, PublicKeyDecoder> decoders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
  static {
    registerPublicKeyDecoder(DSAPublicKeyDecoder.getInstance());
    registerPublicKeyDecoder(RSAPublicKeyDecoder.getInstance());
  }

  private static void registerPublicKeyDecoder(PublicKeyDecoder<?> decoder) {
    for (String type : decoder.supportKeyTypes()) {
      decoders.put(type, decoder);
    }
  }

  PublicKeyAuth(Collection<PublicKey> keys) {
    this.keys = (keys == null) ? Collections.emptyList() : keys;
  }

  @Override
  public boolean authorize(String user, String service, ByteBuf buf, Session session) throws Exception {
    /*
     * byte      SSH_MSG_USERAUTH_REQUEST
     * ....      (fields already consumed before getting here)
     * boolean   FALSE
     * string    public key algorithm name
     * string    public key blob
     */
    boolean hasSig = buf.readBoolean();
    String keyType = ByteBufIo.readUtf8(buf);

    // save the start position of blob
    int blobPos = buf.readerIndex();
    int blobLen = buf.readInt();
    byte[] blob = new byte[blobLen];
    buf.readBytes(blob);

    // read public key from blob
    PublicKeyDecoder<?> decoder = decoders.get(keyType);
    if (decoder == null) {
      throw new InvalidKeySpecException("No decoder available for this key type: " + keyType);
    }
    PublicKey publicKey = decoder.decode(blob);

    boolean match = false;
    for (PublicKey key : keys) {
      if (Comparator.compare(key, publicKey)) {
        match = true;
      }
    }

    String remoteAddr = session.getRemoteAddress();
    if (!match) {
      logger.debug("[{}@{}] Public key not found in server - '{}'", user, remoteAddr, publicKey);

      return false;
    }

    if (!hasSig) {
      session.replyUserAuthPkOk(keyType, blob);

      throw new SshAuthInProgressException("Authentication is in progress... user: " + user
          + ", algorithm: " + keyType);
    }

    /*
     * https://tools.ietf.org/html/rfc4252#section-7"
     *
     * To perform actual authentication... The signature is sent using the following packet
     *
     * byte      SSH_MSG_USERAUTH_REQUEST
     * ....      (fields already consumed before getting here)
     * string    signature
     */
    byte[] sig = ByteBufIo.readBytes(buf);

    Signature verifier = Objects.requireNonNull(SignatureFactories.create(keyType, publicKey));

    /*
     * The value of 'signature' is a signature by the corresponding private
     * key over the following data, in the following order:
     *
     *  string    session identifier
     *  byte      SSH_MSG_USERAUTH_REQUEST
     *  string    user name
     *  string    service name
     *  string    "publickey"
     *  boolean   TRUE
     *  string    public key algorithm name
     *  string    public key to be used for authentication
     *
     * When the server receives this message, it MUST check whether the
     * supplied key is acceptable for authentication, and if so, it MUST
     * check whether the signature is correct.
     */
    ByteBuf val = session.createBuffer();
    ByteBufIo.writeBytes(val, session.getId());
    val.writeByte(SshMessage.SSH_MSG_USERAUTH_REQUEST);
    ByteBufIo.writeUtf8(val, user);
    ByteBufIo.writeUtf8(val, service);
    ByteBufIo.writeUtf8(val, "publickey");
    val.writeBoolean(true);
    ByteBufIo.writeUtf8(val, keyType);
    val.writeBytes(buf, blobPos, 4 + blobLen);

    verifier.update(val);

    return verifier.verify(sig);
  }
}
