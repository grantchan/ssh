package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.NamedFactory;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

public enum MethodFactories implements NamedFactory<Method> {

  publickey("publickey") {
    @Override
    public Method create() {
      return new DirBasedPublicKeyAuth();
    }
  };

  public static final Collection<MethodFactories> values =
      Collections.unmodifiableCollection(EnumSet.allOf(MethodFactories.class));

  private String name;

  MethodFactories(String name) {
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
    MethodFactories f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create();
  }
}