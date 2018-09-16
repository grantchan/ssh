package io.github.grantchan.ssh.util;

public final class KeyUtil {

  public static byte[] resizeKey(byte[] array, int newSize) {
    if (array.length > newSize) {
      byte[] tmp = new byte[newSize];
      System.arraycopy(array, 0, tmp, 0, newSize);
      array = tmp;
    }
    return array;
  }

}
