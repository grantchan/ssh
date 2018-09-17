package io.github.grantchan.ssh.util;

public final class ByteUtil {

  public static byte[] resizeKey(byte[] array, int newSize) {
    if (array.length > newSize) {
      byte[] tmp = new byte[newSize];
      System.arraycopy(array, 0, tmp, 0, newSize);
      array = tmp;
    }
    return array;
  }

  public static byte[] htonl(long i) {
    byte[] n = new byte[4];
    n[0] = (byte) (i >>> 24);
    n[1] = (byte) (i >>> 16);
    n[2] = (byte) (i >>> 8);
    n[3] = (byte) i;

    return n;
  }
}
