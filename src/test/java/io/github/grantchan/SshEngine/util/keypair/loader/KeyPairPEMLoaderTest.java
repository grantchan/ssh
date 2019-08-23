package io.github.grantchan.SshEngine.util.keypair.loader;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KeyPairPEMLoaderTest {

  private Path keyPairFolder;

  @Before
  public void setUp() throws URISyntaxException {
    keyPairFolder = Paths.get(getClass().getResource(getClass().getSimpleName() + ".class")
                                        .toURI())
                         .getParent();
  }

  @Test
  public void testLoadDSAKeyPairFromFile() throws IOException, GeneralSecurityException,
                                                  IllegalAccessException {
    Path keyPairFile = keyPairFolder.resolve("id_dsa_test");
    assertTrue(Files.exists(keyPairFile));

    KeyPair kp = DSAKeyPairPEMLoader.getInstance().load(keyPairFile);
    assertNotNull(kp);
  }

  @Test
  public void testLoadRSAKeyPairFromFile() throws IOException, GeneralSecurityException,
                                                  IllegalAccessException {
    Path keyPairFile = keyPairFolder.resolve("id_rsa_test");
    assertTrue(Files.exists(keyPairFile));

    KeyPair kp = RSAKeyPairPEMLoader.getInstance().load(keyPairFile);
    assertNotNull(kp);
  }
}