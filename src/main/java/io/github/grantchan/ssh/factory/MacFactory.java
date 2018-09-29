package io.github.grantchan.ssh.factory;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.util.ByteUtil;
import io.netty.util.internal.StringUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum MacFactory implements NamedObject, Factory<Mac> {

  hmacsha1("hmac-sha1", "HmacSHA1", 20, 20);

  public static final Set<MacFactory> values =
      Collections.unmodifiableSet(EnumSet.allOf(MacFactory.class));

  private String name;
  private String transformation;
  private int blkSize;
  private int defBlkSize;

  MacFactory(String name, String transformation, int blkSize, int defBlkSize) {
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
  public Mac create(Object... params) throws Exception {
    if (params == null || params.length != 1) {
      throw new IllegalArgumentException("Bad parameters for " + getName());
    }

    Mac mac = Mac.getInstance(transformation);
    assert mac != null;

    byte[] key = (byte[]) params[0];

    key = ByteUtil.resizeKey(key, getDefBlkSize());
    Key sks = new SecretKeySpec(key, transformation);
    mac.init(sks);

    return mac;
  }

  public static MacFactory fromName(String name) {
    if (StringUtil.isNullOrEmpty(name)) {
      return null;
    }

    for (MacFactory f : values) {
      if (name.equalsIgnoreCase(f.getName())) {
        return f;
      }
    }

    return null;
  }
}
