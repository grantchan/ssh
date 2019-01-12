package io.github.grantchan.ssh.util.buffer;

import io.netty.buffer.ByteBuf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public final class SshByteBuf {

  /**
   * Read a byte array from a {@link ByteBuf}
   * <p>The byte array in the {@code buf} is represented as a uint32 containing its length (number
   * of bytes that follow) followed by a byte array</p>
   *
   * @param buf  the {@link ByteBuf} object to read from
   * @return     the byte array read from the {@code buf}
   * @see        #writeBytes(ByteBuf, byte[])
   */
  public static byte[] readBytes(ByteBuf buf) {
    Objects.requireNonNull(buf, "Cannot read data from a null ByteBuf object");

    byte[] val = new byte[buf.readInt()];
    buf.readBytes(val);

    return val;
  }

  /**
   * Write a byte array to a {@link ByteBuf}
   * <p>The byte array is stored in the {@code buf} as a uint32 containing its length (number of
   * bytes that follow) and zero (means empty string) or more bytes that are the byte array</p>
   *
   * @param buf  the {@link ByteBuf} object be written into
   * @param val  the byte array to be stored in the {@code buf}
   * @see        #readBytes(ByteBuf)
   */
  public static void writeBytes(ByteBuf buf, byte[] val) {
    Objects.requireNonNull(buf, "Cannot write data to a null ByteBuf object");

    if (val == null) {
      return;
    }

    buf.writeInt(val.length);
    buf.writeBytes(val);
  }

  /**
   * Read a string from a {@link ByteBuf}
   *
   * @param buf  the {@link ByteBuf} object to read from
   * @return     the UTF-8 string read from the {@code buf}
   * @see        #writeUtf8(ByteBuf, String)
   */
  public static String readUtf8(ByteBuf buf) {
    Objects.requireNonNull(buf, "Cannot read UTF-8 string from a null ByteBuf object");

    byte[] val = new byte[buf.readInt()];
    buf.readBytes(val);

    return new String(val, StandardCharsets.UTF_8);
  }

  /**
   * Write a string to a {@link ByteBuf}
   *
   * @param buf  the {@link ByteBuf} object be written into
   * @param val  the UTF-8 string to be copied into the {@code buf}
   * @return     number of bytes written into the {@code buf}
   * @see        #readUtf8(ByteBuf)
   */
  public static int writeUtf8(ByteBuf buf, String val) {
    Objects.requireNonNull(buf, "Cannot write UTF-8 string to a null ByteBuf object");

    if (val == null) {
      return 0;
    }

    int idx = buf.writerIndex();

    buf.writeInt(val.length());
    buf.writeBytes(val.getBytes(StandardCharsets.UTF_8));

    return buf.writerIndex() - idx;
  }

  /**
   * Read a multiple precision integer from a {@link ByteBuf}
   *
   * @param buf  the {@link ByteBuf} object to read from
   * @return     the {@link BigInteger} read from {@code buf}
   * @see        #writeMpInt(ByteBuf, BigInteger)
   */
  public static BigInteger readMpInt(ByteBuf buf) {
    Objects.requireNonNull(buf, "Cannot read integer from a null ByteBuf object");

    int len = buf.readInt();
    byte[] b = new byte[len];
    buf.readBytes(b);

    return new BigInteger(b);
  }

  /**
   * Write a multiple precision integer to a {@link ByteBuf}
   *
   * @param buf  the {@link ByteBuf} object be written into
   * @param i    the integer, represented as a BigInteger object, to be copied into the {@code buf}
   * @return     the updated {@code buf}
   * @see        #writeMpInt(ByteBuf, byte[])
   */
  public static ByteBuf writeMpInt(ByteBuf buf, BigInteger i) {
    Objects.requireNonNull(buf, "Cannot write integer to a null ByteBuf object");

    if (i == null) {
      return buf;
    }

    byte[] val = i.toByteArray();

    return writeMpInt(buf, val);
  }

  /**
   * Write a multiple precision integer to a {@link ByteBuf}
   *
   * @param buf  the {@link ByteBuf} object be written into
   * @param val  the integer, represented by a byte array, to be copied into the {@code buf}
   * @return     the updated {@code buf}
   * @see #writeMpInt(ByteBuf, BigInteger)
   */
  public static ByteBuf writeMpInt(ByteBuf buf, byte[] val) {
    Objects.requireNonNull(buf, "Cannot write integer to a null ByteBuf object");

    if (val == null) {
      return buf;
    }

    if ((val[0] & 0x80) != 0) {
      buf.writeInt(val.length + 1 /* padding */);
      buf.writeByte(0);
    } else {
      buf.writeInt(val.length);
    }
    buf.writeBytes(val);

    return buf;
  }

  /* Private constructor to prevent this class from being explicitly instantiated */
  private SshByteBuf() {}
}
