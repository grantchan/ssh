package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;
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

  private Iterator<KeyPair> keyPairs;

  PublicKeyAuth(Collection<KeyPair> keyPairs) {
    this.keyPairs = Objects.requireNonNull(keyPairs).iterator();
  }

  @Override
  public boolean submit(Session session) {
    if (!keyPairs.hasNext()) {
      logger.debug("No more available key to submit for authentication");

      return false;
    }

    KeyPair current = keyPairs.next();

    PublicKey key = current.getPublic();

    logger.debug("Sending key to authenticate, key: {}", key);

    String algo = null;
    if (key instanceof DSAPublicKey) {
      algo = "ssh-dss";
    } else if (key instanceof RSAPublicKey) {
      algo = "ssh-rsa";
    }

    try {
      session.requestUserAuthRequest(session.getUsername(), "ssh-connection", "publickey", algo, key);
    } catch (IOException e) {
      e.printStackTrace();
    }

    return true;
  }

  @Override
  public boolean authenticate(Session session) {
    return false;
  }
}
