package io.github.grantchan.sshengine.util.publickey.decoder;

import io.github.grantchan.sshengine.util.iostream.Reader;
import io.netty.util.internal.StringUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public interface PublicKeyDecoder<T extends PublicKey> {

  Collection<String> supportTypes();

  default boolean support(String type) {
    return supportTypes().contains(type);
  }

  default T decode(byte[] key) throws IOException, GeneralSecurityException,
                                      IllegalAccessException {
    try (InputStream stream = new ByteArrayInputStream(key)) {
      return decode(stream);
    }
  }

  default T decode(InputStream key) throws IOException, GeneralSecurityException,
                                           IllegalAccessException {
    String type = Reader.readLengthUtf8(key);
    if (StringUtil.isNullOrEmpty(type)) {
      throw new StreamCorruptedException("Incomplete key record - key type is missing");
    }

    if (!support(type)) {
      throw new InvalidKeySpecException("Invalid or unsupported key type: " + type + ", expected: "
                                        + String.join(",", supportTypes()));
    }

    return decode0(key);
  }

  T decode0(InputStream key) throws IOException, GeneralSecurityException, IllegalAccessException;

  PublicKeyDecoder<? extends PublicKey> ALL = aggregate(
      Arrays.asList(
          DSAPublicKeyDecoder.getInstance(),
          RSAPublicKeyDecoder.getInstance()
      )
  );

  static PublicKeyDecoder<PublicKey> aggregate(
      Collection<? extends PublicKeyDecoder<? extends PublicKey>> decoders) {
    if (decoders == null) {
      return null;
    }

    return new PublicKeyDecoder<PublicKey>() {
      @Override
      public Collection<String> supportTypes() {
        Collection<String> allTypes = new ArrayList<>();

        for (PublicKeyDecoder<? extends PublicKey> decoder : decoders) {
          allTypes.addAll(decoder.supportTypes());
        }

        return allTypes;
      }

      @Override
      public boolean support(String type) {
        for (PublicKeyDecoder<? extends PublicKey> decoder : decoders) {
          if (decoder.support(type)) {
            return true;
          }
        }

        return false;
      }

      @Override
      public PublicKey decode(InputStream key) throws IOException, GeneralSecurityException,
                                                      IllegalAccessException {
        String type = Reader.readLengthUtf8(key);
        if (StringUtil.isNullOrEmpty(type)) {
          throw new StreamCorruptedException("Incomplete key record - key type is missing");
        }

        for (PublicKeyDecoder<? extends PublicKey> decoder : decoders) {
          if (decoder.support(type)) {
            return decoder.decode0(key);
          }
        }

        return null;
      }

      @Override
      public PublicKey decode0(InputStream key) throws IllegalAccessException {
        throw new IllegalAccessException("This method SHOULD NOT BE EXPLICITLY CALLED");
      }
    };
  }


}
