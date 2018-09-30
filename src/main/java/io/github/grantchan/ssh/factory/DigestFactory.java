package io.github.grantchan.ssh.factory;

import java.security.MessageDigest;

public enum DigestFactory implements NamedFactory<MessageDigest> {

  sha1("sha-1"),
  sha256("sha-256");

  private String name;

  DigestFactory(String name) {
    this.name = name;
  }

  @Override
  public MessageDigest create(Object... params) throws Exception {
    if (params != null && params.length != 0) {
      throw new IllegalArgumentException("Bad parameters for " + getName());
    }

    return MessageDigest.getInstance(name);
  }

  @Override
  public String getName() {
    return this.name;
  }
}
