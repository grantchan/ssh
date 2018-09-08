package io.github.grantchan.ssh.kex;

import java.math.BigInteger;

public class DHSpec {

  private BigInteger p; // safe prime;
  private BigInteger g; // generator for subgroup

  public DHSpec(BigInteger p, BigInteger g) {
    this.p = p;
    this.g = g;
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getG() {
    return g;
  }
}
