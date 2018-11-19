package io.github.grantchan.ssh.userauth;

public class PublicKeyEntry {

  private String type;
  private byte[] data;
  private String comment;

  public PublicKeyEntry(String type, byte[] data, String comment) {
    this.type = type;
    this.data = data;
    this.comment = comment;
  }
}
