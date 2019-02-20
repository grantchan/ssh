package io.github.grantchan.ssh.common.transport.mac;

import io.github.grantchan.ssh.common.NamedObject;
import io.github.grantchan.ssh.util.buffer.Bytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

public enum MacFactories implements NamedObject, MacFactory {

  hmacsha1("hmac-sha1", "HmacSHA1", 20, 20);

  private static final Set<MacFactories> values =
      Collections.unmodifiableSet(EnumSet.allOf(MacFactories.class));

  private String name;
  private String transformation;
  private int blkSize;
  private int defBlkSize;

  MacFactories(String name, String transformation, int blkSize, int defBlkSize) {
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

    key = Bytes.resize(key, getDefBlkSize());
    Key sks = new SecretKeySpec(key, transformation);
    try {
      Objects.requireNonNull(mac).init(sks);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return mac;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static MacFactories from(String name) {
    return NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
  }

  @Override
  public String toString() {
    return name + "[" + transformation + "," + blkSize + "," + defBlkSize + "]";
  }
}
