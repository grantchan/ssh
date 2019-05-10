package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

public enum MethodFactories implements NamedObject, MethodFactory {

  publickey("publickey") {
    @Override
    public Method create(ClientSession session) {
      return new DirBasedPublicKeyAuth(session);
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

  public static Method create(String name, ClientSession session) {
    MethodFactories f = NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
    return (f == null) ? null : f.create(session);
  }
}
