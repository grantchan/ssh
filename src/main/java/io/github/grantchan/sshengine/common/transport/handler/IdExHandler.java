package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.common.transport.kex.KexProposal;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;

public interface IdExHandler extends SessionHolder {

  /*
   * RFC 4253: The maximum length of the string is 255 characters,
   * including the Carriage Return and Line Feed.
   */
  int MAX_IDENTIFICATION_LINE_LENGTH = 255;

  /*
   * Get the remote peer's identification
   * @return the identification if successful, otherwise null.
   */
  static String getId(ByteBuf buf) {
    Objects.requireNonNull(buf, "Parameter cannot be null");

    int rIdx = buf.readerIndex();
    int wIdx = buf.writerIndex();
    if (rIdx == wIdx) {
      return null;
    }

    int line = 1, pos = 0;
    boolean needLf = false;
    boolean validLine = false;

    byte[] data = new byte[MAX_IDENTIFICATION_LINE_LENGTH];

    rIdx--;
    while (rIdx++ < wIdx) {
      byte b = buf.getByte(rIdx);

      if (b == '\0') {
        throw new IllegalStateException("Illegal identification - null character found at" +
            " line #" + line + " character #" + (pos + 1));
      }

      if (b == '\r') {
        needLf = true;

        continue;
      }

      if (b == '\n') {
        line++;

        if (validLine) {
          buf.readerIndex(rIdx + 1);
          buf.discardReadBytes();

          return new String(data, 0, pos, StandardCharsets.UTF_8);
        }

        pos = 0;
        needLf = false;

        continue;
      }

      if (needLf) {
        throw new IllegalStateException("Illegal identification - invalid line ending at" +
            " line #" + line + " character #" + pos + 1);
      }

      if (pos > data.length) {
        throw new IllegalStateException("Illegal identification - line too long at line #" + line +
            " character #" + pos + 1);
      }

      if (pos < 4) {
        data[pos++] = b;
      } else if (data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-') {
        validLine = true;
        data[pos++] = b;
      }
    }

    return null;
  }

  /*
   * Construct the key exchange initialization packet.
   */
  static byte[] kexInit() {
    SecureRandom rand = new SecureRandom();

    byte[] cookie = new byte[SshConstant.MSG_KEX_COOKIE_SIZE];
    rand.nextBytes(cookie);

    int i = 0;
    String[] pp = new String[KexProposal.ALL.size()];
    for (KexProposal p : KexProposal.ALL) {
      pp[i++] = p.getProposals().get();
    }

    return Bytes.concat(
        cookie,
        Bytes.joinWithLength(pp),
        new byte[]{0},  // first factory packet follows
        Bytes.toBigEndian(0)  // reserved (FFU)
    );
  }
}
