package io.github.grantchan.ssh.util;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SshByteBufUtil {

  public static byte[] readBytes(ByteBuf buf) {
    byte[] val = new byte[buf.readInt()];
    buf.readBytes(val);

    return val;
  }

  public static void writeBytes(ByteBuf buf, byte[] val) {
    buf.writeInt(val.length);
    buf.writeBytes(val);
  }

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

  public static ByteBuf writeMpInt(ByteBuf buf, BigInteger i) {
    byte[] val = i.toByteArray();

    return writeMpInt(buf, val);
  }

  public static ByteBuf writeMpInt(ByteBuf buf, byte[] val) {
    if ((val[0] & 0x80) != 0) {
      buf.writeInt(val.length + 1 /* padding */);
      buf.writeByte(0);
    } else {
      buf.writeInt(val.length);
    }
    buf.writeBytes(val);

    return buf;
  }
}
