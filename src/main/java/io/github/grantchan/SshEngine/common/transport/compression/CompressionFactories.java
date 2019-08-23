package io.github.grantchan.SshEngine.common.transport.compression;

import io.github.grantchan.SshEngine.common.NamedFactory;
import io.github.grantchan.SshEngine.common.NamedObject;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CompressionFactories implements NamedFactory<Compression> {

  none("none") {
    @Override
    public Compression create() {
      return null;
    }
  },
  delayedZLib("zlib@openssh.com") {
    @Override
    public Compression create() {
      return new DelayedZLib();
    }
  };

  private static final Set<CompressionFactories> ALL =
      Collections.unmodifiableSet(EnumSet.allOf(CompressionFactories.class));

  private final String name;

  CompressionFactories(String name) {
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

  public static String getNames() {
    return NamedObject.getNames(ALL);
  }

  public static CompressionFactories from(String name) {
    return NamedObject.find(name, ALL, String.CASE_INSENSITIVE_ORDER);
  }

  @Override
  public String toString() {
    return name;
  }
}
