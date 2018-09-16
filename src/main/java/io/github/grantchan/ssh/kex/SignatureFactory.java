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

  public static final Set<SignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SignatureFactory.class));

  private String name;
  private String transformation;

  SignatureFactory(String name, String transformation) {
    this.name = name;
    this.transformation = transformation;
  }

  @Override
  public Signature create(Object... params) throws Exception {
    return Signature.getInstance(transformation);
  }

  @Override
  public String getName() {
    return this.name;
  }
}
