package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SshSignatureFactory implements NamedFactory<Signature> {

  rsa("ssh-rsa", "SHA1withRSA");

  public static final Set<SshSignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SshSignatureFactory.class));

  public static String getNames() {
    return NamedObject.getNames(SshSignatureFactory.values);
  }

  private String name;
  private String transformation;

  SshSignatureFactory(String name, String transformation) {
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
}
