package io.github.grantchan.ssh.trans.signature;

import io.github.grantchan.ssh.common.NamedObject;

import java.security.Key;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinSignatureFactory implements NamedObject, SignatureFactory {

  rsa("ssh-rsa") {
    @Override
    public Signature create(Key key) {
      return new RSASignature(key);
    }
  },
  dsa("ssh-dss") {
    @Override
    public Signature create(Key key) {
      return new DSASignature(key);
    }
  };

  public static final Set<BuiltinSignatureFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinSignatureFactory.class));

  private String name;

  BuiltinSignatureFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static Signature create(String name, Key key) {
    BuiltinSignatureFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(key);
  }
}
