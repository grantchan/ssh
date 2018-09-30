package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.Compression;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CompressionFactory implements NamedFactory<Compression> {

  none("none");

  private static final Set<CompressionFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(CompressionFactory.class));

  public static String getNames() {
    return NamedObject.getNames(CompressionFactory.values);
  }

  private final String name;

  CompressionFactory(String name) {
    this.name = name;
  }

  @Override
  public Compression create(Object... params) throws Exception {
    return null;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
