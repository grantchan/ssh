package io.github.grantchan.ssh.userauth.method;

import io.github.grantchan.ssh.userauth.PublicKeyEntry;
import io.netty.util.internal.StringUtil;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.*;

public class FileBasedPublicKeyAuth extends PublicKeyAuth {

  public FileBasedPublicKeyAuth() {
    this(new File("~/.ssh/authorized_keys"));
  }

  public FileBasedPublicKeyAuth(File authorizedKeysFile) {
    super(deserializeKeys(authorizedKeysFile));
  }

  private static Collection<PublicKey> deserializeKeys(File authorizedKeysFile) {
    Objects.requireNonNull(authorizedKeysFile);

    try (InputStream is = new FileInputStream(authorizedKeysFile)) {
      try (Reader rdr = new InputStreamReader(is, StandardCharsets.UTF_8)) {
        try (BufferedReader brdr = new BufferedReader(rdr)) {
          List<PublicKeyEntry> entries = null;

          for (String ln = brdr.readLine(); ln != null; ln = brdr.readLine()) {
            PublicKeyEntry e = parsePublicKeyEntry(ln);
            if (e == null) {
              continue;
            }

            if (entries == null) {
              entries = new ArrayList<>();
            }
            entries.add(e);
          }
        }
      }

    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  private static PublicKeyEntry parsePublicKeyEntry(String line) {
    if (StringUtil.isNullOrEmpty(line)) {
      return null;
    }
    if (line.charAt(0) == '#') {
      return null;
    }

    String[] i = line.split(" ");
    if (i.length < 2) {
      return null;
    }

    Base64.Decoder decoder = Base64.getDecoder();
    byte[] data = decoder.decode(i[1]);

    return new PublicKeyEntry(i[0], data);
  }
}
