package io.github.grantchan.ssh.common;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;

public final class SshConstant {

  public static final int SSH_PACKET_LENGTH        = 4; // a 32-bit of integer
  public static final int SSH_PADDING_LENGTH       = 1; // a 8-bit of byte
  public static final int SSH_PACKET_HEADER_LENGTH = SSH_PACKET_LENGTH + SSH_PADDING_LENGTH;
  public static final int MSG_KEX_COOKIE_SIZE      = 16;

  // SSH op codes
  public static final byte SSH_MSG_SERVICE_REQUEST        = 5;
  public static final byte SSH_MSG_KEXINIT                = 20;
  public static final byte SSH_MSG_NEWKEYS                = 21;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
  public static final byte SSH_MSG_KEX_DH_GEX_GROUP       = 31;
  public static final byte SSH_MSG_KEX_DH_GEX_INIT        = 32;
  public static final byte SSH_MSG_KEX_DH_GEX_REPLY       = 33;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST     = 34;

  private static boolean isNumberic(Class<?> clazz) {
    if (clazz == null) {
      return false;
    } else if (Number.class.isAssignableFrom(clazz)) {
      return true;
    }

    return Arrays.asList(Byte.TYPE, Short.TYPE, Integer.TYPE, Long.TYPE,
        Float.TYPE, Double.TYPE).indexOf(clazz) >= 0;
  }

  private static Integer toInteger(Number num) {
    if (num == null) {
      return null;
    } else if (num instanceof Integer) {
      return (Integer) num;
    }

    return num.intValue();
  }

  public static String messageName(int cmd) {
    for (Field f : SshConstant.class.getFields()) {
      String name = f.getName();
      if (!name.startsWith("SSH_MSG_")) {
        continue;
      }

      int mod = f.getModifiers();
      if (!Modifier.isPublic(mod) || !Modifier.isFinal(mod) || !Modifier.isStatic(mod)) {
        continue;
      }

      Class<?> type = f.getType();
      if (!isNumberic(type)) {
        continue;
      }

      Number val;
      try {
        val = (Number) f.get(null);
      } catch (IllegalAccessException e) {
        continue;
      }

      if (toInteger(val).equals(cmd)) {
        return name;
      }
    }
    return null;
  }
}