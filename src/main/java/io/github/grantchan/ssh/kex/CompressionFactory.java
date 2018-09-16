package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CompressionFactory implements NamedObject, Factory<Compression> {

  none("none");

  public static final Set<CompressionFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(CompressionFactory.class));

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
