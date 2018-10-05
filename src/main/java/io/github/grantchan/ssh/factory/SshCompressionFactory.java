package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.Compression;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SshCompressionFactory implements NamedFactory<Compression> {

  none("none");

  private static final Set<SshCompressionFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SshCompressionFactory.class));

  public static String getNames() {
    return NamedObject.getNames(SshCompressionFactory.values);
  }

  private final String name;

  SshCompressionFactory(String name) {
    this.name = name;
  }

  @Override
  public Compression create() {
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
