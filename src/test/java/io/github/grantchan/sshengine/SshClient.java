package io.github.grantchan.sshengine;

import io.github.grantchan.sshengine.client.ClientSession;

import java.util.Optional;

public class SshClient {
  public static void main(String[] args) {
      try (Ssh client = new Ssh()) {
        client.start();

        try (ClientSession session = client.connect("127.0.0.1", 22).get()) {
          Optional.ofNullable(session).ifPresent(s -> {
            System.out.println("Connection established");

            try {
              Boolean isAuthed = session.auth("guest", null).get();
              Optional.ofNullable(isAuthed).ifPresent(authResult -> {

                if (!authResult) {
                  System.out.println("Login failed");
                  return;
                }

                System.out.println("Authentication completed");

              });

            } catch (Exception e) {
              e.printStackTrace();
            }
          });
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
  }
}
