package io.github.grantchan.sshengine.server.userauth.method;

import io.github.grantchan.sshengine.util.System;
import io.github.grantchan.sshengine.util.publickey.decoder.PublicKeyDecoder;
import io.netty.util.internal.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class FileBasedPublicKeyAuth extends PublicKeyAuth {

  private static final Logger logger = LoggerFactory.getLogger(FileBasedPublicKeyAuth.class);

  private static final FileBasedPublicKeyAuth instance = new FileBasedPublicKeyAuth();

  private FileBasedPublicKeyAuth() {
    this(System.getUserHomeFolder().resolve(".ssh/authorized_keys").toFile());
  }

  private FileBasedPublicKeyAuth(File authorizedKeysFile) {
    super(deserializeKeys(authorizedKeysFile));
  }

  public static FileBasedPublicKeyAuth getInstance() {
    return instance;
  }

  /**
   * Deserialize the text format public key file into {@link PublicKey} array
   * @param authorizedKeysFile  public key file
   * @return                    Array of {@link PublicKey} parsed from {@code authorizedKeyFiles}
   */
  private static Collection<PublicKey> deserializeKeys(File authorizedKeysFile) {
    Objects.requireNonNull(authorizedKeysFile);

    List<PublicKey> keys = null;

    try (InputStream is = new FileInputStream(authorizedKeysFile)) {
      BufferedReader brdr = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));

      for (String ln = brdr.readLine(); ln != null; ln = brdr.readLine()) {
        PublicKey k;
        try {
          k = parsePublicKeyEntry(ln);
        } catch (IOException | GeneralSecurityException | IllegalAccessException e) {
          logger.info("Invalid key line: '{}', ignored.", ln);

          continue;
        }

        if (k == null) {
          continue;
        }

        if (keys == null) {
          keys = new ArrayList<>();
        }
        keys.add(k);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    return keys;
  }

  /**
   * Parse a single line record in key file
   * @param line  key line
   * @return      {@link PublicKey} or {@code null} the line is empty or isn't in valid format
   *
   * @throws IllegalArgumentException  if the line is invalid
   * @throws InvalidKeySpecException   if decoder is not available for this key type
   * @throws IOException               if error happens while reading the key line
   * @throws GeneralSecurityException  if key type is not supported by system
   */
  private static PublicKey parsePublicKeyEntry(String line) throws IOException,
                                                                   GeneralSecurityException,
                                                                   IllegalAccessException {
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

    PublicKeyDecoder<?> decoder = PublicKeyDecoder.ALL;
    if (!decoder.support(type)) {
      throw new InvalidKeySpecException("Decoder is not available for this key type: " + type);
    }
    return decoder.decode(data);
  }
}
