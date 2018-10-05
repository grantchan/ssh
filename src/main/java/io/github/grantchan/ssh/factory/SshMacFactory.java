package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.util.ByteUtil;
import io.netty.util.internal.StringUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum SshMacFactory implements NamedObject, MacFactory {

  hmacsha1("hmac-sha1", "HmacSHA1", 20, 20);

  private static final Set<SshMacFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(SshMacFactory.class));

  public static String getNames() {
    return NamedObject.getNames(SshMacFactory.values);
  }

  private String name;
  private String transformation;
  private int blkSize;
  private int defBlkSize;

  SshMacFactory(String name, String transformation, int blkSize, int defBlkSize) {
    this.name = name;
    this.transformation = transformation;
    this.blkSize = blkSize;
    this.defBlkSize = defBlkSize;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public int getBlkSize() {
    return this.blkSize;
  }

  public int getDefBlkSize() {
    return this.defBlkSize;
  }

  @Override
  public Mac create(byte[] key) {
    Mac mac = null;
    try {
      mac = Mac.getInstance(transformation);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    assert mac != null;

    key = ByteUtil.resizeKey(key, getDefBlkSize());
    Key sks = new SecretKeySpec(key, transformation);
    try {
      mac.init(sks);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return mac;
  }

  public static SshMacFactory fromName(String name) {
    if (StringUtil.isNullOrEmpty(name)) {
      return null;
    }

    for (SshMacFactory f : values) {
      if (name.equalsIgnoreCase(f.getName())) {
        return f;
      }
    }
    return null;
  }
}
