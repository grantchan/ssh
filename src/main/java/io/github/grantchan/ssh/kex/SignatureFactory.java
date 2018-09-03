package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SignatureFactory implements NamedObject, Factory<Signature> {

  rsa("ssh-rsa", "SHA1withRSA");

  private static Signature instance = null;

  public static final Set<SignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SignatureFactory.class));

  private String name;
  private String transformation;

  SignatureFactory(String name, String transformation) {
    this.name = name;
    this.transformation = transformation;
  }

  @Override
  public Signature create() throws Exception {
    if (instance == null) {
      instance = Signature.getInstance(transformation);
    }
    return instance;
  }

  @Override
  public String getName() {
    return null;
  }
}
