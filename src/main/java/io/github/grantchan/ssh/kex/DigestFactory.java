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

  public static MessageDigest instance = null;

  public static final Set<DigestFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(DigestFactory.class));

  private String name;

  DigestFactory(String name) {
    this.name = name;
  }

  @Override
  public MessageDigest create() throws Exception {
    if (instance == null) {
      instance = MessageDigest.getInstance(name);
    }
    return instance;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
