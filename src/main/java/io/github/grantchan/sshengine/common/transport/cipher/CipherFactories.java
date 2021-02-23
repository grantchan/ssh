package io.github.grantchan.sshengine.common.transport.cipher;

import io.github.grantchan.sshengine.common.NamedObject;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.util.buffer.Bytes;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

public enum CipherFactories implements NamedObject, CipherFactory {

  aes256cbc("aes256-cbc", "AES", "AES/CBC/NoPadding", 16, 32),
  aes256ctr("aes256-ctr", "AES", "AES/CTR/NoPadding", 16, 32);

  private static final Set<CipherFactories> values =
      Collections.unmodifiableSet(EnumSet.allOf(CipherFactories.class));

  private final String name;
  private final String algorithm;
  private final String transformation;
  private final int ivSize;
  private final int blkSize;

  CipherFactories(String name, String algorithm, String transformation, int ivSize, int blkSize) {
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
  public Cipher create(byte[] key, byte[] iv, int mode) throws SshException {
    Cipher cip;
    try {
      cip = Cipher.getInstance(transformation);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      String message =
          String.format("Failed to create cipher instance - name:%s, algorithm:%s, transformation:%s",
              name, algorithm, transformation);

      throw new SshException(message, e);
    }

    key = Bytes.resize(key, getBlkSize());
    iv = Bytes.resize(iv, getIvSize());

    try {
      cip.init(mode, new SecretKeySpec(key, getAlgorithm()), new IvParameterSpec(iv));
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      String message =
          String.format("Failed to initialize cipher instance - mode:%d, algorithm:%s",
              mode, algorithm);

      throw new SshException(message, e);
    }

    return cip;
  }

  public static String getNames() {
    return NamedObject.getNames(values);
  }

  public static CipherFactories from(String name) {
    return NamedObject.find(name, values, String.CASE_INSENSITIVE_ORDER);
  }

  @Override
  public String toString() {
    return name + "[" + algorithm + "," + transformation + "," + ivSize + "," + blkSize + "]";
  }
}
