package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.AbstractClientChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class SshClient {
  private static final Logger logger = LoggerFactory.getLogger(SshClient.class);

  public static void main(String[] args) {
    Ssh client = new Ssh();

    client.start();

    try (ClientSession session = client.connect("127.0.0.1", 22).get()) {
      Optional.ofNullable(session).ifPresent(s -> {
        logger.info("Connection established");

        try {
          Boolean isAuthed = session.auth("guest", null).get();
          Optional.ofNullable(isAuthed).ifPresent(authResult -> {
            if (!authResult) {
              logger.error("Login failed");
              return;
            }

            logger.info("Authentication completed");

            try (AbstractClientChannel channel = session.openChannel("session").get()) {
              Optional.ofNullable(channel).ifPresent(ch -> {
                logger.info("Channel is opened");
              });
            } catch (Exception e) {
              e.printStackTrace();
            }
          });
        } catch (Exception e) {
          e.printStackTrace();
        }
      });
    } catch (Exception e) {
      e.printStackTrace();
    }

    client.stop();
  }
}
