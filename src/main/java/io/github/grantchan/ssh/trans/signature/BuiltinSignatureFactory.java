package io.github.grantchan.ssh.trans.signature;

import io.github.grantchan.ssh.common.NamedFactory;
import io.github.grantchan.ssh.common.NamedObject;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinSignatureFactory implements NamedFactory<Signature> {

  rsa("ssh-rsa", "SHA1withRSA");

  public static final Set<BuiltinSignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinSignatureFactory.class));

  private String name;
  private String transformation;

  BuiltinSignatureFactory(String name, String transformation) {
    this.name = name;
    this.transformation = transformation;
  }

  @Override
  public Signature create() {
    try {
      return Signature.getInstance(transformation);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static Signature create(String name) {
    BuiltinSignatureFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create();
  }
}
