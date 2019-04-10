package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;
import io.github.grantchan.ssh.util.key.deserializer.DSAKeyPairLoader;
import io.github.grantchan.ssh.util.key.deserializer.KeyPairLoader;
import io.github.grantchan.ssh.util.key.deserializer.RSAKeyPairLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Objects;

public class DirBasedPublicKeyAuth extends PublicKeyAuth {

  private static final Logger logger = LoggerFactory.getLogger(DirBasedPublicKeyAuth.class);

  private static final String FILE_NAME_PREFIX = "id_";

  private static final Collection<KeyPairLoader> loaders =
      new ArrayList<>();

  static {
    registerKeyPairDeserializer(DSAKeyPairLoader.getInstance());
    registerKeyPairDeserializer(RSAKeyPairLoader.getInstance());
  }

  private static void registerKeyPairDeserializer(KeyPairLoader deserializer) {
    loaders.add(deserializer);
  }

  public DirBasedPublicKeyAuth(Session session) {
    super(session, loadKeyPairs(getDefaultKeysFolder()));
  }

  public DirBasedPublicKeyAuth(Session session, Path keyPairFolder) {
    super(session, loadKeyPairs(keyPairFolder));
  }

  private static Path getUserHomeFolder() {
    return new File(System.getProperty("user.home")).toPath().toAbsolutePath().normalize();
  }

  private static Path getDefaultKeysFolder() {
    return getUserHomeFolder().resolve(".ssh");
  }

  /**
   * Load key pairs in files inside a folder
   *
   * @param keysFolder Folder to load key pair files from
   * @return a collection of {@link KeyPair}
   */
  private static Collection<KeyPair> loadKeyPairs(Path keysFolder) {
    Collection<String> types = KeyPairTypes.names;
    if (types.size() == 0) {
      return null;
    }

    Collection<KeyPair> keyPairs = null;

    for (String type : types) {
      Path p = keysFolder.resolve(FILE_NAME_PREFIX + type.toLowerCase());
      if (!Files.exists(p)) {
        logger.debug("{} doesn't exist, skipped", p);
        continue;
      }

      KeyPair kp = null;
      try {
        kp = loadKeyPair(p);
      } catch (IOException | GeneralSecurityException e) {
        e.printStackTrace();
      }

      if (kp != null) {
        if (keyPairs == null) {
          keyPairs = new LinkedList<>();
        }
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
  private static KeyPair loadKeyPair(Path file) throws IOException, GeneralSecurityException {
    Objects.requireNonNull(file);

    for (KeyPairLoader loader : loaders) {
      if (loader.support(file)) {
        return loader.load(file);
      }
    }

    return null;
  }
}
