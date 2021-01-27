package io.github.grantchan.sshengine;

public class SshdTest {

  public static void main(String[] args) {
    Sshd server = new Sshd();

    server.open(5222);

    server.close();
  }
}
