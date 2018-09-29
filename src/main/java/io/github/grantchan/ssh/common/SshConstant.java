package io.github.grantchan.ssh.common;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.function.Predicate;

public final class SshConstant {

  public static final int SSH_PACKET_LENGTH        = 4; // a 32-bit of integer
  public static final int SSH_PADDING_LENGTH       = 1; // a 8-bit of byte
  public static final int SSH_PACKET_HEADER_LENGTH = SSH_PACKET_LENGTH + SSH_PADDING_LENGTH;
  public static final int MSG_KEX_COOKIE_SIZE      = 16;

  // SSH op codes
  public static final byte SSH_MSG_DISCONNECT             = 1;
  public static final byte SSH_MSG_SERVICE_REQUEST        = 5;
  public static final byte SSH_MSG_SERVICE_ACCEPT         = 6;
  public static final byte SSH_MSG_KEXINIT                = 20;
  public static final byte SSH_MSG_NEWKEYS                = 21;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
  public static final byte SSH_MSG_KEX_DH_GEX_GROUP       = 31;
  public static final byte SSH_MSG_KEX_DH_GEX_INIT        = 32;
  public static final byte SSH_MSG_KEX_DH_GEX_REPLY       = 33;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST     = 34;

  // SSH connection protocol message (RFC 4254)
  public static final byte SSH_MSG_GLOBAL_REQUEST            = 80;
  public static final byte SSH_MSG_REQUEST_SUCCESS           = 81;
  public static final byte SSH_MSG_REQUEST_FAILURE           = 82;
  public static final byte SSH_MSG_CHANNEL_OPEN              = 90;
  public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
  public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE      = 92;
  public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93;
  public static final byte SSH_MSG_CHANNEL_DATA              = 94;
  public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA     = 95;
  public static final byte SSH_MSG_CHANNEL_EOF               = 96;
  public static final byte SSH_MSG_CHANNEL_CLOSE             = 97;
  public static final byte SSH_MSG_CHANNEL_REQUEST           = 98;
  public static final byte SSH_MSG_CHANNEL_SUCCESS           = 99;
  public static final byte SSH_MSG_CHANNEL_FAILURE           = 100;

  // Disconnect reason code
  public static final int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1;
  public static final int SSH_DISCONNECT_PROTOCOL_ERROR                 = 2;
  public static final int SSH_DISCONNECT_KEY_EXCHANGE_FAILED            = 3;
  public static final int SSH_DISCONNECT_RESERVED                       = 4;
  public static final int SSH_DISCONNECT_MAC_ERROR                      = 5;
  public static final int SSH_DISCONNECT_COMPRESSION_ERROR              = 6;
  public static final int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          = 7;
  public static final int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
  public static final int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9;
  public static final int SSH_DISCONNECT_CONNECTION_LOST                = 10;
  public static final int SSH_DISCONNECT_BY_APPLICATION                 = 11;
  public static final int SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12;
  public static final int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13;
  public static final int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
  public static final int SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15;

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

  private static String getName(int cmd, Predicate<? super Field> filter) {
    for (Field f : SshConstant.class.getFields()) {
      String name = f.getName();
      if (!filter.test(f)) {
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
    return Integer.valueOf(cmd).toString();
  }

  public static String messageName(int cmd) {
    return getName(cmd, f -> f.getName().startsWith("SSH_MSG_"));
  }

  public static String disconnectReason(int code) {
    return getName(code, f -> f.getName().startsWith("SSH_DISCONNECT"));
  }
}