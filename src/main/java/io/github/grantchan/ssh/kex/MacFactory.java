package io.github.grantchan.ssh.kex;

import io.github.grantchan.ssh.common.Factory;
import io.github.grantchan.ssh.common.NamedObject;
import io.netty.util.internal.StringUtil;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum MacFactory implements NamedObject, Factory<Mac> {

  hmacsha1("hmac-sha1", "HmacSHA1", 20, 20);

  private static Mac instance = null;

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
  public Mac create() throws Exception {
    if (instance == null) {
      instance = Mac.getInstance(transformation);
    }
    return instance;
  }

  @Override
  public String getName() {
    return this.name;
  }
}
