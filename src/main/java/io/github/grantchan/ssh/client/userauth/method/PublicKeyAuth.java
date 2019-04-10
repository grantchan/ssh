package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Iterator;
import java.util.Objects;

public class PublicKeyAuth implements Method {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private Session session;
  private Iterator<KeyPair> keyPairs;
  private KeyPair current;

  PublicKeyAuth(Session session, Collection<KeyPair> keyPairs) {
    this.session = session;
    this.keyPairs = Objects.requireNonNull(keyPairs).iterator();
  }

  @Override
  public boolean submit() {
    if (!keyPairs.hasNext()) {
      logger.debug("No more available key to submit for authentication");

      return false;
    }

    String user = session.getUsername();
    String service = "ssh-connection";
    String method = "publickey";

    current = keyPairs.next();
    PublicKey key = current.getPublic();

    logger.debug("Sending key to authenticate, key: {}", key);

    String algo = null;
    if (key instanceof DSAPublicKey) {
      algo = "ssh-dss";
    } else if (key instanceof RSAPublicKey) {
      algo = "ssh-rsa";
    }

    try {
      session.requestUserAuthRequest(user, service, method, algo, key);
    } catch (IOException e) {
      e.printStackTrace();
    }

    return true;
  }

  @Override
  public boolean authenticate(ByteBuf buf) {
    PublicKey currPubKey = current.getPublic();


    return false;
  }
}
