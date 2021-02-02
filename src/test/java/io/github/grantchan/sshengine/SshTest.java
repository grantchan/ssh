package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.client.connection.ClientChannel;

import java.util.Optional;

public class SshTest {

  public static void main(String[] args) {

    Ssh client = new Ssh();
    client.start();

    // ======== connect to create session =============
    try (ClientSession session = client.connect("127.0.0.1", 5222).get()) {

      Optional.ofNullable(session).ifPresent(s -> {
        System.out.println("Connection established");

        // ========== authentication ============
        Boolean isAuth = null;
        try {
          isAuth = session.auth("guest", null).get();
        } catch (Exception e) {
          e.printStackTrace();
        }

        Optional.ofNullable(isAuth).ifPresent(succed -> {
          if (!succed) {
            System.out.println("Login failed");
            return;
          }

          System.out.println("Authentication succeeded");

          // ========== create new channel ===============
          try (ClientChannel channel = session.openChannel("session").get()) {
            Optional.ofNullable(channel).ifPresent(c -> {
              System.out.println("Channel established");

                /*
                    channel.setIn(in);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.waitFor(EnumSet.of(), 0L);
                */
            });
          } catch (Exception e) {
            e.printStackTrace();
          }
        });
      });
    } catch (Exception e) {
      e.printStackTrace();
    }

    client.stop();
  }
}
