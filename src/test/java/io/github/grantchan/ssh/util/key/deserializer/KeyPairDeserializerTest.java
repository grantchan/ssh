package io.github.grantchan.ssh.util.key.deserializer;

import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Objects;

import static org.junit.Assert.assertTrue;

public class KeyPairDeserializerTest {

  @Test
  public void testLoadRSAKeyPairFromFile() throws IOException,
                                                  URISyntaxException,
                                                  GeneralSecurityException {
    Path keyPairFolder = Paths.get(getClass().getResource(getClass().getSimpleName() + ".class")
                                             .toURI())
                         .getParent();
    Objects.requireNonNull(keyPairFolder);

    Path keyPairFile = keyPairFolder.resolve("id_rsa_test");
    assertTrue(Files.exists(keyPairFile));

    // KeyPair kp = RSAKeyPairDeserializer.getInstance().unmarshal(keyPairFile);
  }
}