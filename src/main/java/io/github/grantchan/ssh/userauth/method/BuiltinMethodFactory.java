package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.common.NamedFactory;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum BuiltinMethodFactory implements NamedFactory<Method> {

  password("password") {
    @Override
    public Method create() {
      return null;
    }
  },
  publickey("publickey") {
    @Override
    public Method create() {
      return new FileBasedPublicKeyAuth();
    }
  };

  public static final Set<BuiltinMethodFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(BuiltinMethodFactory.class));

  private String name;

  BuiltinMethodFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static Method create(String name) {
    BuiltinMethodFactory f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create();
  }
}
