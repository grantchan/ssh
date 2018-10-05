package io.github.grantchan.ssh.factory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum SshDigestFactory implements NamedFactory<MessageDigest> {

  sha1("sha-1"),
  sha256("sha-256");

  private String name;

  SshDigestFactory(String name) {
    this.name = name;
  }

  @Override
  public MessageDigest create() {
    try {
      return MessageDigest.getInstance(name);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
