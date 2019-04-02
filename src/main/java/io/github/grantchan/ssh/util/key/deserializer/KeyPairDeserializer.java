package io.github.grantchan.ssh.util.key.deserializer;

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
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public interface KeyPairDeserializer {

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

  default KeyPair unmarshal(Path file) throws IOException, GeneralSecurityException {
    try (InputStream stream = Files.newInputStream(file)) {
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

      return unmarshal(base64.decode(key.trim()));
    }
  }

  KeyPair unmarshal(byte[] bytes) throws IOException, GeneralSecurityException;
}
