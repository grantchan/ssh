package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.util.ByteUtil;
import io.netty.util.internal.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CipherFactory implements NamedFactory<Cipher> {

  aes256cbc("aes256-cbc", "AES", "AES/CBC/NoPadding", 16, 32),
  aes256ctr("aes256-ctr", "AES", "AES/CTR/NoPadding", 16, 32);

  private static final Set<CipherFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(CipherFactory.class));

  public static String getNames() {
    return NamedObject.getNames(CipherFactory.values);
  }

  private final String name;
  private final String algorithm;
  private final String transformation;
  private final int ivSize;
  private final int blkSize;

  CipherFactory(String name, String algorithm, String transformation, int ivSize, int blkSize) {
    this.name = name;
    this.algorithm = algorithm;
    this.transformation = transformation;
    this.ivSize = ivSize;
    this.blkSize = blkSize;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public int getIvSize() {
    return this.ivSize;
  }

  public int getBlkSize() {
    return this.blkSize;
  }

  @Override
  public Cipher create(Object... params) throws Exception {
    if (params == null || params.length != 3) {
      throw new IllegalArgumentException("Bad parameters for " + getName());
    }

    Cipher cip = Cipher.getInstance(transformation);
    assert cip != null;

    byte[] key = (byte[]) params[0];
    byte[] iv  = (byte[]) params[1];
    int mode   = (int) params[2];

    key = ByteUtil.resizeKey(key, getBlkSize());
    iv = ByteUtil.resizeKey(iv, getIvSize());
    cip.init(mode, new SecretKeySpec(key, getAlgorithm()), new IvParameterSpec(iv));

    return cip;
  }

  public static CipherFactory fromName(String name) {
    if (StringUtil.isNullOrEmpty(name)) {
      return null;
    }

    for (CipherFactory f : values) {
      if (name.equalsIgnoreCase(f.getName())) {
        return f;
      }
    }

    return null;
  }
}
