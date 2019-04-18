package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.System;
import io.github.grantchan.ssh.util.keypair.loader.KeyPairPEMLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Objects;

public class DirBasedPublicKeyAuth extends PublicKeyAuth {

  private static final Logger logger = LoggerFactory.getLogger(DirBasedPublicKeyAuth.class);

  private static final String FILE_NAME_PREFIX = "id_";

  public DirBasedPublicKeyAuth(Session session) {
    super(session, loadKeyPairs(session, getDefaultKeysFolder()));
  }

  public DirBasedPublicKeyAuth(Session session, Path keyPairFolder) {
    super(session, loadKeyPairs(session, keyPairFolder));
  }

  private static Path getDefaultKeysFolder() {
    return System.getUserHomeFolder().resolve(".ssh");
  }

  /**
   * Load key pairs in files inside a folder
   *
   * @param keysFolder Folder to load key pair files from
   * @return a collection of {@link KeyPair}
   */
  private static Collection<KeyPair> loadKeyPairs(Session session, Path keysFolder) {
    Collection<String> types = KeyPairTypes.names;
    if (types.size() == 0) {
      return null;
    }

    Collection<KeyPair> keyPairs = null;

    for (String type : types) {
      Path p = keysFolder.resolve(FILE_NAME_PREFIX + type.toLowerCase());
      if (!Files.exists(p)) {
        logger.debug("[{}] {} doesn't exist, skipped", session, p);
        continue;
      }

      KeyPair kp = null;
      try {
        kp = loadKeyPair(p);
      } catch (IOException | GeneralSecurityException | IllegalAccessException e) {
        e.printStackTrace();
      }

      if (kp != null) {
        if (keyPairs == null) {
          keyPairs = new LinkedList<>();
        }
        logger.debug("[{}] {} is loaded", session, p);

        keyPairs.add(kp);
      }
    }

    return keyPairs;
  }

  /**
   * Load key pair from file
   *
   * @param file key pair file
   * @return a {@link KeyPair} object loaded from {@code file}
   */
  private static KeyPair loadKeyPair(Path file) throws IOException, GeneralSecurityException,
                                                       IllegalAccessException {
    Objects.requireNonNull(file);

    KeyPairPEMLoader loader = KeyPairPEMLoader.ALL;
    return loader.load(file);
  }
}
