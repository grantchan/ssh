package io.github.grantchan.sshengine.client.userauth.method;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.transport.signature.Signature;
import io.github.grantchan.sshengine.common.transport.signature.SignatureFactories;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.github.grantchan.sshengine.util.buffer.LengthBytesBuilder;
import io.github.grantchan.sshengine.util.publickey.PublicKeyUtil;
import io.github.grantchan.sshengine.util.publickey.decoder.PublicKeyDecoder;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Objects;

public class PublicKeyAuth extends AbstractLogger
                           implements Method {

  private ClientSession session;
  private Iterator<KeyPair> keyPairs;
  private KeyPair current;

  PublicKeyAuth(ClientSession session, Collection<KeyPair> keyPairs) {
    this.session = session;
    this.keyPairs = Objects.requireNonNull(keyPairs).iterator();
  }

  @Override
  public boolean submit() {
    if (!keyPairs.hasNext()) {
      logger.debug("[{}] No more available key to submit for authentication", session);

      return false;
    }

    String user = session.getUsername();
    String service = "ssh-connection";
    String method = "publickey";

    current = keyPairs.next();
    PublicKey key = current.getPublic();

    logger.debug("[{}] Sending key to authenticate...", session);

    String algo = PublicKeyUtil.typeOf(key);

    try {
      session.requestUserAuthRequest(user, service, method, algo, key);
    } catch (IOException e) {
      e.printStackTrace();
    }

    return true;
  }

  @Override
  public boolean authenticate(ByteBuf buf) throws IOException,
                                                  GeneralSecurityException,
                                                  IllegalAccessException {
    String keyType = ByteBufIo.readUtf8(buf);

    byte[] blob = new byte[buf.readInt()];
    buf.readBytes(blob);

    PublicKey recvPubKey = PublicKeyDecoder.ALL.decode(blob);

    PublicKey pubKey = current.getPublic();
    if (!PublicKeyUtil.compare(pubKey, recvPubKey)) {
      throw new InvalidKeySpecException("Public keys mismatched");
    }

    String user = session.getUsername();
    String service = "ssh-connection";
    String method = "publickey";

    String algo = PublicKeyUtil.typeOf(pubKey);

    Signature signer = SignatureFactories.create(keyType, current.getPrivate());
    Objects.requireNonNull(signer);

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
        LengthBytesBuilder.concat(session.getId()),
        new byte[] {SshMessage.SSH_MSG_USERAUTH_REQUEST},
        LengthBytesBuilder.concat(user, service, "publickey"),
        LengthBytesBuilder.concat(true),
        LengthBytesBuilder.concat(keyType),
        LengthBytesBuilder.concat(blob)
    );

    signer.update(data);

    byte[] sig = Bytes.concat(
        LengthBytesBuilder.concat(algo),
        LengthBytesBuilder.concat(signer.sign())
    );

    session.requestUserAuthRequest(user, service, method, algo, pubKey, sig);

    return true;
  }
}
