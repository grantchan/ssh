package io.github.grantchan.sshengine.server.userauth.method;

import io.github.grantchan.sshengine.util.LazySupplier;
import io.github.grantchan.sshengine.util.System;
import io.github.grantchan.sshengine.util.publickey.decoder.PublicKeyDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class FileBasedPublicKeyAuth extends PublicKeyAuth {

  private static final Logger logger = LoggerFactory.getLogger(FileBasedPublicKeyAuth.class);

  private static final LazySupplier<Path> AUTHORIZED_KEY_FILE_PATH_HOLDER =
      new LazySupplier<Path>() {
        @Override
        protected Path initialize() {
          return System.getUserHomeFolder().resolve(".ssh/authorized_keys");
        }
      };

  private static final FileBasedPublicKeyAuth instance = new FileBasedPublicKeyAuth();

  private FileBasedPublicKeyAuth() {
    this(AUTHORIZED_KEY_FILE_PATH_HOLDER.get().toFile());
  }

  private FileBasedPublicKeyAuth(File authorizedKeysFile) {
    super(deserializeKeys(authorizedKeysFile));
  }

  public static FileBasedPublicKeyAuth getInstance() {
    return instance;
  }

  /**
   * Deserialize the text format public key file into {@link PublicKey} array
   *
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
          logger.warn("Invalid key line: '{}', ignored.", ln);

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
    } catch (FileNotFoundException e) {
      logger.error("Unable to find the authorized key file - {}", authorizedKeysFile.getPath());
    } catch (IOException e) {
      logger.error("Failed to read from the authorized key file - {}", authorizedKeysFile.getPath());
    }

    return keys == null ? Collections.emptyList() : keys;
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
  private static PublicKey parsePublicKeyEntry(String line) throws GeneralSecurityException,
                                                                   IllegalAccessException,
                                                                   IOException {
    Objects.requireNonNull(line, "Invalid parameter - line cannot be null");

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
