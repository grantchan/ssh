package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.handler.KexHandler;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SshKexFactory implements NamedFactory<KexHandler> {

  dhgexsha1("diffie-hellman-group-exchange-sha1") {
    @Override
    public KexHandler create() {
      return new KexHandler(SshDigestFactory.sha1.create());
    }
  },
  dhgexsha256("diffie-hellman-group-exchange-sha256") {
    @Override
    public KexHandler create() {
      return new KexHandler(SshDigestFactory.sha256.create());
    }
  };

  public static final Set<SshKexFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SshKexFactory.class));

  public static String getNames() {
    return NamedObject.getNames(SshKexFactory.values);
  }

  public String name;

  SshKexFactory(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return this.name;
  }

}
