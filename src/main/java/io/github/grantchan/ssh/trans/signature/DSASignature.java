package io.github.grantchan.ssh.trans.signature;

import java.security.Key;

public class DSASignature extends Signature {

  public DSASignature(Key key) {
    this("SHA1withDSA", key);
  }

  public DSASignature(String transformation, Key key) {
    super(transformation, key);
  }
}
