package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class DirBasedPublicKeyAuth extends PublicKeyAuth {

  public DirBasedPublicKeyAuth() {
    super(loadKeyPairs(getDefaultKeysFolder()));
  }

  public DirBasedPublicKeyAuth(Session session, Path keyPairFolder) {
    super(loadKeyPairs(keyPairFolder));
  }

  private static Path getUserHomeFolder() {
    return new File(System.getProperty("user.home")).toPath().toAbsolutePath().normalize();
  }

  private static Path getDefaultKeysFolder() {
    return getUserHomeFolder().resolve(".ssh");
  }

  private static Collection<KeyPair> loadKeyPairs(Path keysFolder) {
    try (InputStream is = Files.newInputStream(keysFolder)) {
      List<String> lines = new BufferedReader(
          new InputStreamReader(is, StandardCharsets.UTF_8)).lines().collect(Collectors.toList());

      return loadKeyPairs(lines);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  private static Collection<KeyPair> loadKeyPairs(List<String> lines) {
    return null;
  }
}
