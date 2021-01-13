package io.github.grantchan.sshengine.server.userauth.method;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.transport.signature.Signature;
import io.github.grantchan.sshengine.common.transport.signature.SignatureFactories;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.github.grantchan.sshengine.util.publickey.PublicKeyUtil;
import io.github.grantchan.sshengine.util.publickey.decoder.PublicKeyDecoder;
import io.netty.buffer.ByteBuf;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class PublicKeyAuth extends AbstractLogger implements Method {

  private final Collection<PublicKey> keys;

  PublicKeyAuth(Collection<PublicKey> keys) {
    this.keys = (keys == null) ? Collections.emptyList() : keys;
  }

  @Override
  public boolean authorize(String user, String service, ByteBuf buf, ServerSession session) throws Exception {
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
    byte[] blob = new byte[buf.readInt()];
    buf.readBytes(blob);

    // read public key from blob
    PublicKeyDecoder<?> decoder = PublicKeyDecoder.ALL;
    PublicKey publicKey = decoder.decode(blob);

    boolean match = false;
    for (PublicKey key : keys) {
      if (PublicKeyUtil.compare(key, publicKey)) {
        match = true;
        break;
      }
    }

    if (!match) {
      logger.debug("[{}] Public key not found in server - '{}'", session, publicKey);

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
    byte[] data = Bytes.concat(
        Bytes.addLen(session.getRawId()),
        new byte[] {SshMessage.SSH_MSG_USERAUTH_REQUEST},
        Bytes.joinWithLength(user, service, "publickey"),
        Bytes.toArray(true),
        Bytes.addLen(keyType),
        Bytes.addLen(blob)
    );

    verifier.update(data);

    return verifier.verify(sig);
  }
}
