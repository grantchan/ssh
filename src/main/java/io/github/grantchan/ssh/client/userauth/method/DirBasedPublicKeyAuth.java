package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.util.key.deserializer.DSAKeyPairDeserializer;
import io.github.grantchan.ssh.util.key.deserializer.KeyPairDeserializer;
import io.github.grantchan.ssh.util.key.deserializer.RSAKeyPairDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.*;
import java.util.stream.Collectors;

public class DirBasedPublicKeyAuth extends PublicKeyAuth {

  private static final Logger logger = LoggerFactory.getLogger(DirBasedPublicKeyAuth.class);

  private static final String FILE_NAME_PREFIX = "id_";

  private static final Collection<KeyPairDeserializer> loaders =
      new ArrayList<>();
  static {
    registerKeyPairDeserializer(DSAKeyPairDeserializer.getInstance());
    registerKeyPairDeserializer(RSAKeyPairDeserializer.getInstance());
  }

  private static void registerKeyPairDeserializer(KeyPairDeserializer deserializer) {
    loaders.add(deserializer);
  }

  public DirBasedPublicKeyAuth() {
    super(loadKeyPairs(getDefaultKeysFolder()));
  }

  public DirBasedPublicKeyAuth(Path keyPairFolder) {
    super(loadKeyPairs(keyPairFolder));
  }

  private static Path getUserHomeFolder() {
    return new File(System.getProperty("user.home")).toPath().toAbsolutePath().normalize();
  }

  private static Path getDefaultKeysFolder() {
    return getUserHomeFolder().resolve(".ssh");
  }

  /**
   * Load key pairs in files inside a folder
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
      }

      try (InputStream is = Files.newInputStream(p)) {
        List<String> lines = new BufferedReader(
            new InputStreamReader(is, StandardCharsets.UTF_8)).lines()
                                                              .collect(Collectors.toList());

        if (keyPairs == null) {
          keyPairs = new LinkedList<>();
        }

        keyPairs.addAll(loadKeyPairs(lines));
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    return keyPairs;
  }

  /**
   * Load key pairs from an ascii file content
   * @param lines Lines of strings normally read from a key pair file
   * @return a collection of {@link KeyPair}
   */
  private static Collection<KeyPair> loadKeyPairs(List<String> lines) {
    for (KeyPairDeserializer loader : loaders) {
      if (loader.support(lines)) {
        return loader.unmarshal(lines);
      }
    }

    return Collections.emptyList();
  }
}
