package io.github.grantchan.ssh.util;

import io.netty.buffer.ByteBuf;

import java.nio.charset.StandardCharsets;

public class SshByteBufUtil {

  public static String readUtf8(ByteBuf buf) {
    byte[] val = new byte[buf.readInt()];
    buf.readBytes(val);

    return new String(val, StandardCharsets.UTF_8);
  }

  public static int writeUtf8(ByteBuf buf, String val) {
    int idx = buf.writerIndex();

    buf.writeInt(val.length());
    buf.writeBytes(val.getBytes(StandardCharsets.UTF_8));

    return buf.writerIndex() - idx;
  }
}
