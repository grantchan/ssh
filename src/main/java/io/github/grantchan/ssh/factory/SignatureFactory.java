package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;

import java.security.Signature;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SignatureFactory implements NamedFactory<Signature> {

  rsa("ssh-rsa", "SHA1withRSA");

  public static final Set<SignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SignatureFactory.class));

  public static String getNames() {
    return NamedObject.getNames(SignatureFactory.values);
  }

  private String name;
  private String transformation;

  SignatureFactory(String name, String transformation) {
    this.name = name;
    this.transformation = transformation;
  }

  @Override
  public Signature create(Object... params) throws Exception {
    if (params != null && params.length != 0) {
      throw new IllegalArgumentException("Bad parameters for " + getName());
    }

    return Signature.getInstance(transformation);
  }

  @Override
  public String getName() {
    return this.name;
  }
}
