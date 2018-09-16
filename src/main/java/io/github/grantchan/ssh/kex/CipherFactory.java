package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.util.KeyUtil;
import io.netty.util.internal.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CipherFactory implements NamedObject, Factory<Cipher> {

  aes256cbc("aes256-cbc", "AES", "AES/CBC/NoPadding", 16, 32),
  aes256ctr("aes256-ctr", "AES", "AES/CTR/NoPadding", 16, 32);

  public static final Set<CipherFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(CipherFactory.class));

  private String name;
  private String algorithm;
  private String transformation;
  private int ivSize;
  private int blkSize;

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

  public int getBlkSize() {
    return this.blkSize;
  }

  public int getIvSize() {
    return this.ivSize;
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

    key = KeyUtil.resizeKey(key, getBlkSize());
    iv = KeyUtil.resizeKey(iv, getIvSize());
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
