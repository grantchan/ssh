package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum DigestFactory implements NamedObject, Factory<MessageDigest> {

  sha1("sha1"),
  sha256("sha256");

  private String name;

  DigestFactory(String name) {
    this.name = name;
  }

  @Override
  public MessageDigest create(Object... params) throws Exception {
    return MessageDigest.getInstance(name);
  }

  @Override
  public String getName() {
    return this.name;
  }
}
