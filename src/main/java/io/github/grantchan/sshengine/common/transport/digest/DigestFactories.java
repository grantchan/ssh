package io.github.grantchan.sshengine.common.transport.digest;

import io.github.grantchan.sshengine.common.NamedFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum DigestFactories implements NamedFactory<MessageDigest> {

  md5("MD5"),
  sha1("SHA-1"),
  sha256("SHA-256"),
  sha384("SHA-384"),
  sha512("SHA-512");

  private String name;

  DigestFactories(String name) {
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
