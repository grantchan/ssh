package io.github.grantchan.sshengine.arch;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * <p>Protocol packets have message numbers in the range 1 to 255. These
 * numbers are allocated as follows: </p>
 *
 * <p>Transport layer protocol:<br>
 * 1 to 19    Transport layer generic (e.g., disconnect, ignore,
 * debug, etc.)<br>
 * 20 to 29   Algorithm negotiation<br>
 * 30 to 49   Key exchange method specific (numbers can be reused<br>
 * for different authentication methods)</p>
 *
 * <p>User authentication protocol:<br>
 * 50 to 59   User authentication generic<br>
 * 60 to 79   User authentication method specific (numbers can be
 * reused for different authentication methods)</p>
 *
 * <p>Connection protocol:
 * 80 to 89   Connection protocol generic<br>
 * 90 to 127  Channel related messages</p>
 *
 * <p>Reserved for client protocols:<br>
 * 128 to 191 Reserved</p>
 *
 * <p>Local extensions:<br>
 * 192 to 255 Local extensions</p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc4250#section-4.1.1">Message Numbers</a>
 */
public final class SshMessage {

  // Message Numbers
  // <a href="https://tools.ietf.org/html/rfc4250#section-4.1.2">Initial Assignments</a>
  public static final byte SSH_MSG_DISCONNECT                = 1;   // [SSH-TRANS]
  public static final byte SSH_MSG_IGNORE                    = 2;   // [SSH-TRANS]
  public static final byte SSH_MSG_UNIMPLEMENTED             = 3;   // [SSH-TRANS]
  public static final byte SSH_MSG_DEBUG                     = 4;   // [SSH-TRANS]
  public static final byte SSH_MSG_SERVICE_REQUEST           = 5;   // [SSH-TRANS]
  public static final byte SSH_MSG_SERVICE_ACCEPT            = 6;   // [SSH-TRANS]
  public static final byte SSH_MSG_KEXINIT                   = 20;  // [SSH-TRANS]
  public static final byte SSH_MSG_NEWKEYS                   = 21;  // [SSH-TRANS]

  public static final byte SSH_MSG_USERAUTH_REQUEST          = 50;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_FAILURE          = 51;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_SUCCESS          = 52;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_BANNER           = 53;  // [SSH-USERAUTH]

  public static final byte SSH_MSG_USERAUTH_PK_OK            = 60;  // [SSH-USERAUTH]

  public static final byte SSH_MSG_GLOBAL_REQUEST            = 80;  // [SSH-CONNECT]
  public static final byte SSH_MSG_REQUEST_SUCCESS           = 81;  // [SSH-CONNECT]
  public static final byte SSH_MSG_REQUEST_FAILURE           = 82;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_OPEN              = 90;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE      = 92;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_DATA              = 94;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA     = 95;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_EOF               = 96;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_CLOSE             = 97;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_REQUEST           = 98;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_SUCCESS           = 99;  // [SSH-CONNECT]
  public static final byte SSH_MSG_CHANNEL_FAILURE           = 100; // [SSH-CONNECT]

  // Diffie-Hellman Key Exchange Message Numbers
  public static final byte SSH_MSG_KEXDH_INIT  = 30;
  public static final byte SSH_MSG_KEXDH_REPLY = 31;

  // Diffie-Hellman Group Exchange Message Numbers
  // <a href="https://tools.ietf.org/html/rfc4419#section-5">Summary of Message Numbers</a>
  /**
   * SSH_MSG_KEX_DH_GEX_REQUEST_OLD is used for backward compatibility.<br>
   * Instead of sending "min || n || max", the client only sends "n".<br>In
   * addition, the hash is calculated using only "n" instead of "min || n
   * || max".
   */
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
  public static final byte SSH_MSG_KEX_DH_GEX_GROUP       = 31;
  public static final byte SSH_MSG_KEX_DH_GEX_INIT        = 32;
  public static final byte SSH_MSG_KEX_DH_GEX_REPLY       = 33;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST     = 34;

  // Disconnection Messages Reason Codes and Descriptions
  // <a href="https://tools.ietf.org/html/rfc4250#section-4.2.2">Initial Assignments</a>
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
    for (Field f : SshMessage.class.getFields()) {
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

  /**
   * Gets the message string from a command value
   * @param cmd  the command value
   * @return     the message string
   */
  public static String from(int cmd) {
    return getName(cmd, f -> f.getName().startsWith("SSH_MSG_"));
  }

  /**
   * Gets the disconnect reason from a code value
   * @param code  the reason code
   * @return      the reason string
   */
  public static String disconnectReason(int code) {
    return getName(code, f -> f.getName().startsWith("SSH_DISCONNECT"));
  }
}