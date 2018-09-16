package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum KexFactory implements NamedObject, Factory<Kex> {

  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public Kex create(Object... params) throws Exception {
      return new Kex(DigestFactory.sha1.create());
    }
  };

  public static final Set<KexFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(KexFactory.class));

  public String name;

  KexFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
