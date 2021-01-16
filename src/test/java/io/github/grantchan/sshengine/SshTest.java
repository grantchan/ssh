package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.AbstractClientChannel;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class SshTest {

  @Test
  public void testNormalConnection() throws Exception {
    try (Sshd sshd = new Sshd()) {
      sshd.open(11111);

      Ssh ssh = new Ssh();
      ssh.start();

      try (ClientSession session = ssh.connect("127.0.0.1", 11111).get(1, TimeUnit.SECONDS)) {
        assertNotNull("Failed to establish connection", session);

        try {
          assertTrue("Authentication failed", session.auth("guest", null).get(1, TimeUnit.SECONDS));
          try (AbstractClientChannel channel =
                   session.openChannel("session").get(1, TimeUnit.SECONDS)) {
            assertNotNull("Unable to open new channel", channel);
          }
        } catch (Exception e) {
          fail("Failed to authenticate");
        }
      }

      ssh.stop();
    }
  }
}
