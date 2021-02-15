package io.github.grantchan.sshengine.util.keypair.loader;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class KeyPairPEMLoaderTest {

  private final Path keyPairFolder;

  public KeyPairPEMLoaderTest() throws URISyntaxException {
    this.keyPairFolder =
        Paths.get(getClass().getResource(getClass().getSimpleName() + ".class").toURI()).getParent();
  }

  @Parameter
  public String keyPairFilename;

  @Parameters (name = "{index}: test file={0}")
  public static Collection<Object> parameters() {
    return Arrays.asList(new Object[] {
        "id_dsa_test", "id_rsa_test"
    });
  }

  @Test
  public void testLoadKeyPairFromFile() throws IOException, GeneralSecurityException,
                                                  IllegalAccessException {
    Path keyPairFile = keyPairFolder.resolve(keyPairFilename);
    assertTrue(Files.exists(keyPairFile));

    KeyPair kp = KeyPairPEMLoader.ALL.load(keyPairFile);
    assertNotNull(kp);
  }
}