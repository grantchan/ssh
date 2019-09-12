package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.common.transport.kex.KexInitProposal;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.github.grantchan.sshengine.util.buffer.LengthBytesBuilder;
import io.netty.buffer.ByteBuf;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;

import static io.github.grantchan.sshengine.arch.SshConstant.MSG_KEX_COOKIE_SIZE;

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

    final String[] id = {null};

    ByteProcessor findId = new ByteProcessor() {
      private int line = 1, pos = 0;
      private boolean needLf = false;
      private boolean validLine = false;

      private byte[] data = new byte[MAX_IDENTIFICATION_LINE_LENGTH];

      @Override
      public boolean process(byte b) {

        /* RFC 4253: The null character MUST NOT be sent. */
        if (b == '\0') {
          throw new IllegalStateException("Illegal identification - null character found at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (b == '\r') {
          needLf = true;
          return true;
        }

        if (b == '\n') {
          line++;

          if (validLine) {
            id[0] = new String(data, 0, pos, StandardCharsets.UTF_8);
            return false;
          }
          pos = 0;
          needLf = false;
          return true;
        }

        if (needLf) {
          throw new IllegalStateException("Illegal identification - invalid line ending at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (pos > data.length) {
          throw new IllegalStateException("Illegal identification - line too long at" +
              " line #" + line + " character #" + pos + 1);
        }

        if (pos < 4) {
          data[pos++] = b;
        } else if (data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-') {
          validLine = true;
          data[pos++] = b;
        }

        return true;
      }
    };

    int i = buf.forEachByte(rIdx, wIdx - rIdx, findId);
    if (i == -1) {
      // packet is not fully received, restore reader index and return
      buf.readerIndex(rIdx);
      return null;
    }

    buf.readerIndex(i + 1);
    buf.discardReadBytes();

    return id[0];
  }

  /*
   * Construct the key exchange initialization packet.
   */
  static byte[] kexInit() {
    SecureRandom rand = new SecureRandom();

    byte[] cookie = new byte[MSG_KEX_COOKIE_SIZE];
    rand.nextBytes(cookie);

    LengthBytesBuilder lbb = new LengthBytesBuilder();
    KexInitProposal.ALL.forEach(p -> {
      lbb.append(p.getProposals().get());
    });

    return Bytes.concat(
        cookie,
        lbb.toBytes(),
        new byte[]{0},  // first factory packet follows
        Bytes.htonl(0)  // reserved (FFU)
    );
  }
}
