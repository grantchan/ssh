package io.github.grantchan.SshEngine.common.transport.signature;

import io.github.grantchan.SshEngine.common.NamedObject;

import java.security.Key;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SignatureFactories implements NamedObject, SignatureFactory {

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

  public static final Set<SignatureFactories> values =
      Collections.unmodifiableSet(EnumSet.allOf(SignatureFactories.class));

  private String name;

  SignatureFactories(String name) {
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
    SignatureFactories f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(key);
  }
}
