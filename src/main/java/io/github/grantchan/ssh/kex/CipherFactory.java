package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;
import io.netty.util.internal.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum CipherFactory implements NamedObject, Factory<Cipher> {

  aes256cbc("aes256-cbc", "AES/CBC/NoPadding", 16, 32),
  aes256ctr("aes256-ctr", "AES/CTR/NoPadding", 16, 32);

  private static Cipher instance = null;

  public static final Set<CipherFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(CipherFactory.class));

  private String name;
  private String transformation;
  private int ivSize;
  private int blkSize;

  CipherFactory(String name, String transformation, int ivSize, int blkSize) {
    this.name = name;
    this.transformation = transformation;
    this.ivSize = ivSize;
    this.blkSize = blkSize;
  }

  @Override
  public Cipher create() throws Exception {
    if (instance == null) {
      instance = Cipher.getInstance(transformation);
    }
    return instance;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
