package io.github.grantchan.ssh.util.keypair.loader;

import io.netty.util.internal.StringUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.*;
import java.util.stream.Collectors;

public interface KeyPairPEMLoader {

  String getBeginLine();

  String getEndLine();

  default boolean support(Path file) throws IOException {
    try (InputStream stream = Files.newInputStream(file)) {
      List<String> lines = new BufferedReader(
          new InputStreamReader(stream, StandardCharsets.UTF_8)).lines()
                                                                .collect(Collectors.toList());

      if (lines.size() == 0) {
        return false;
      }

      String beginLine = getBeginLine();
      if (StringUtil.isNullOrEmpty(beginLine)) {
        return false;
      }

      for (String line: lines) {
        if (line.contains(beginLine)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Transform the private key file into {@link KeyPair} object.
   *
   * The file is encoded in PEM format - defined in RFCs 1421 through 1424, is a container format
   * that may include private key. The name is from Privacy Enhanced Mail (PEM), a failed method
   * for secure email but the container format it used lives on, and is a base64 translation of the
   * x509 ASN.1 keys.
   *
   * @param pem the file in PEM format to transform from
   * @return The {@link KeyPair} object represents the key pair
   * @throws IOException if any error happens when reading the file
   * @throws GeneralSecurityException if the file content is invalid
   */
  default KeyPair load(Path pem) throws IOException, GeneralSecurityException,
                                        IllegalAccessException {
    try (InputStream stream = Files.newInputStream(pem)) {
      List<String> lines = new BufferedReader(
          new InputStreamReader(stream, StandardCharsets.UTF_8)).lines()
                                                                .collect(Collectors.toList());
      if (lines.size() == 0) {
        return null;
      }

      int startLnIdx = Integer.MAX_VALUE;
      int endLnIdx = Integer.MIN_VALUE;
      for (int i = 0; i < lines.size(); i++) {
        String ln = lines.get(i);
        if (ln.contains(getBeginLine())) {
          startLnIdx = i;
        } else if (ln.contains(getEndLine())) {
          endLnIdx = i;
          break;
        }
      }

      if (startLnIdx >= endLnIdx) {
        return null;
      }

      String key = String.join("", lines.subList(++startLnIdx, endLnIdx));
      Base64.Decoder base64 = Base64.getDecoder();

      return load(base64.decode(key.trim()));
    }
  }

  KeyPair load(byte[] keyBytes) throws IOException, GeneralSecurityException, IllegalAccessException;

  KeyPairPEMLoader ALL = aggregate(
      Arrays.asList(DSAKeyPairPEMLoader.getInstance(),
                    RSAKeyPairPEMLoader.getInstance()
      )
  );

  static KeyPairPEMLoader aggregate(Collection<KeyPairPEMLoader> loaders) {
    if (loaders == null) {
      return null;
    }

    return new KeyPairPEMLoader() {
      @Override
      public String getBeginLine() {
        return null;
      }

      @Override
      public String getEndLine() {
        return null;
      }

      @Override
      public boolean support(Path file) throws IOException {
        Objects.requireNonNull(file);

        for (KeyPairPEMLoader loader : loaders) {
          if (loader.support(file)) {
            return true;
          }
        }
        return false;
      }

      @Override
      public KeyPair load(Path pem) throws IOException, GeneralSecurityException,
                                           IllegalAccessException {
        Objects.requireNonNull(pem);

        for (KeyPairPEMLoader loader : loaders) {
          if (loader.support(pem)) {
            return loader.load(pem);
          }
        }
        return null;
      }

      @Override
      public KeyPair load(byte[] keyBytes) throws IllegalAccessException {
        throw new IllegalAccessException("This method SHOULD NOT BE EXPLICITLY CALLED");
      }
    };
  }
}
