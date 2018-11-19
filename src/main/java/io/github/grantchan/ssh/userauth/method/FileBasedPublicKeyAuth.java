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

  /**
   * Parse a single line record in key file
   * @param line  key line
   * @return      {@link PublicKeyEntry} or {@code null} the line is empty or isn't in valid format
   * @throws IllegalArgumentException if the line is invalid
   */
  private static PublicKeyEntry parsePublicKeyEntry(String line) throws IllegalArgumentException {
    if (StringUtil.isNullOrEmpty(line)) {
      return null;
    }
    if (line.charAt(0) == '#') {
      return null;
    }

    String[] fields = line.split(" ");
    if (fields.length < 2) {
      throw new IllegalArgumentException("Illegal key record - no delimiter between key type and key data");
    }

    String type = fields[0];
    Base64.Decoder base64 = Base64.getDecoder();
    byte[] data = base64.decode(fields[1]);
    String comment = fields.length == 3 ? fields[2] : null;

    return new PublicKeyEntry(type, data, comment);
  }
}
