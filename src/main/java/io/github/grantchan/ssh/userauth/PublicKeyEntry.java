package io.github.grantchan.ssh.userauth;

public class PublicKeyEntry {

  private String type;
  private byte[] data;

  public PublicKeyEntry(String type, byte... data) {
    this.type = type;
    this.data = data;
  }
}
