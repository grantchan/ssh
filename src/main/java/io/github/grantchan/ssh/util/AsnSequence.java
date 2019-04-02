package io.github.grantchan.ssh.util;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Objects;

public class AsnSequence extends FilterInputStream {

  public AsnSequence(byte[] bytes) {
    this(new ByteArrayInputStream(Objects.requireNonNull(bytes)));
  }

  public AsnSequence(InputStream stream) {
    super(Objects.requireNonNull(stream));
  }

  public BigInteger readInteger() {
    return null;
  }
}
