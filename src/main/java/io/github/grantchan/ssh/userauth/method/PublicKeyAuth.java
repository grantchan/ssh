package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.arch.SshIoUtil;
import io.github.grantchan.ssh.trans.signature.BuiltinSignatureFactory;
import io.github.grantchan.ssh.util.KeyComparator;
import io.netty.buffer.ByteBuf;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class PublicKeyAuth implements Method {

  private final Collection<PublicKey> keys;

  public PublicKeyAuth(Collection<PublicKey> keys) {
    this.keys = (keys == null) ? Collections.emptyList() : keys;
  }

  @Override
  public boolean authenticate(String user, String service, ByteBuf buf) throws Exception {

    boolean hasSig = buf.readBoolean();
    String algorithm = SshIoUtil.readUtf8(buf);
    int length = buf.readInt();
    PublicKey publicKey = SshIoUtil.readPublicKey(buf);

    boolean match = false;
    for (PublicKey key : keys) {
      if (KeyComparator.compare(key, publicKey)) {
        match = true;
      }
    }

    if (!match) {
      return false;
    }

    if (!hasSig) {
      throw new SshAuthInProgressException("Authentication is in progress... user: " + user + ", algorithm: "
          + algorithm);
    }

    Signature verifier = Objects.requireNonNull(BuiltinSignatureFactory.create(algorithm));
    verifier.initVerify(publicKey);

    return false;
  }
}
