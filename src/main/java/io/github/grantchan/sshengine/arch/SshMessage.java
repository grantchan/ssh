package io.github.grantchan.sshengine.arch;

import io.github.grantchan.sshengine.util.LazySupplier;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * This class defines the SSH message identifiers.
 *
 * <p>Protocol packets have message numbers in the range 1 to 255. These numbers are allocated as
 * follows: </p>
 *
 * <ul>
 *   <li>
 *     Transport layer protocol:<ul>
 *       <li>1 to 19   Transport layer generic (e.g., disconnect, ignore, debug, etc.)</li>
 *       <li>20 to 29  Algorithm negotiation</li>
 *       <li>30 to 49  Key exchange method specific (numbers can be reused for different
 *           authentication methods)</li></ul>
 *   </li>
 *
 *   <li>
 *     User authentication protocol:<ul>
 *       <li>50 to 59  User authentication generic</li>
 *       <li>60 to 79  User authentication method specific (numbers can be reused for different
 *           authentication methods)</li></ul>
 *   </li>
 *
 *   <li>
 *     Connection protocol:<ul>
 *       <li>80 to 89  Connection protocol generic</li>
 *       <li>90 to 127  Channel related messages</li></ul>
 *   </li>
 *
 *   <li>
 *     Reserved for client protocols:<ul>
 *       <li>128 to 191 Reserved</li></ul>
 *   </li>
 *
 *   <li>
 *     Local extensions:<ul>
 *       <li>192 to 255 Local extensions</li></ul>
 *   </li>
 * </ul>
 * @see <a href="https://tools.ietf.org/html/rfc4250#section-4.1.1">Message Numbers</a>
 */
public final class SshMessage {

  /*
   * Message Numbers
   *
   * @see <a href="https://tools.ietf.org/html/rfc4250#section-4.1.2">Initial Assignments</a>
   */
  public static final byte SSH_MSG_DISCONNECT                = 1;   // [SSH-TRANS]
  public static final byte SSH_MSG_IGNORE                    = 2;   // [SSH-TRANS]
  public static final byte SSH_MSG_UNIMPLEMENTED             = 3;   // [SSH-TRANS]
  public static final byte SSH_MSG_DEBUG                     = 4;   // [SSH-TRANS]
  public static final byte SSH_MSG_SERVICE_REQUEST           = 5;   // [SSH-TRANS]
  public static final byte SSH_MSG_SERVICE_ACCEPT            = 6;   // [SSH-TRANS]

  public static final byte SSH_MSG_KEXINIT                   = 20;  // [SSH-TRANS]
  public static final byte SSH_MSG_NEWKEYS                   = 21;  // [SSH-TRANS]

  // User authentication
  public static final byte SSH_MSG_USERAUTH_REQUEST          = 50;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_FAILURE          = 51;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_SUCCESS          = 52;  // [SSH-USERAUTH]
  public static final byte SSH_MSG_USERAUTH_BANNER           = 53;  // [SSH-USERAUTH]

  // "public key" method
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

  /*
   * Diffie-Hellman Group Exchange Message Numbers
   *
   * SSH_MSG_KEX_DH_GEX_REQUEST_OLD is used for backward compatibility.<br>
   * Instead of sending "min || n || max", the client only sends "n".<br>
   * In addition, the hash is calculated using only "n" instead of "min || n || max".
   *
   * @see <a href="https://tools.ietf.org/html/rfc4419#section-5">Summary of Message Numbers</a>
   */
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
  public static final byte SSH_MSG_KEX_DH_GEX_GROUP       = 31;
  public static final byte SSH_MSG_KEX_DH_GEX_INIT        = 32;
  public static final byte SSH_MSG_KEX_DH_GEX_REPLY       = 33;
  public static final byte SSH_MSG_KEX_DH_GEX_REQUEST     = 34;

  /* Disconnection Messages Reason Codes and Descriptions
   *
   * @see <a href="https://tools.ietf.org/html/rfc4250#section-4.2.2">Initial Assignments</a>
   */
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

  /**
   * Checks if the given class is one of the numeric classes - Byte, Short, Integer, Long, Float,
   * Double.
   *
   * @param clazz The class to check its type
   * @return      True if {@code clazz} belongs to the class set mentioned above, otherwise false.
   */
  private static boolean isNumeric(Class<?> clazz) {
    if (clazz == null) {
      return false;
    }

    if (Number.class.isAssignableFrom(clazz)) {
      return true;
    }

    return Arrays.asList(Byte.TYPE, Short.TYPE, Integer.TYPE, Long.TYPE,
        Float.TYPE, Double.TYPE).indexOf(clazz) >= 0;
  }

  /**
   * Reflect current class to invert all public, final, static and numeric fields(variables) that
   * satisfies the eligible condition.
   *
   * @param eligible The {@link Predicate} to customize the scan for specific type of field.
   * @return         A {@link Map} stores the inverted field content.
   */
  private static Map<Integer, List<String>> invertFields(Predicate<? super Field> eligible) {
    return Arrays.stream(SshMessage.class.getFields())
                 .filter(f -> {
                   if (!eligible.test(f)) {
                     return false;
                   }

                   int mod = f.getModifiers();
                   if (!Modifier.isPublic(mod) ||
                       !Modifier.isFinal(mod) ||
                       !Modifier.isStatic(mod)) {
                     return false;
                   }

                   return isNumeric(f.getType());
                 })
                 .collect(Collectors.groupingBy(f -> {
                   try {
                     return f.getInt(null);
                   } catch (IllegalAccessException e) {
                     return -1;
                   }
                 }, TreeMap::new, Collectors.mapping(Field::getName, Collectors.toList())));
  }

  private static final LazySupplier<Map<Integer, List<String>>> MESSAGE_INDEX =
      new LazySupplier<Map<Integer, List<String>>>() {
        @Override
        protected Map<Integer, List<String>> initialize() {
          return invertFields(f -> f.getName().startsWith("SSH_MSG_"));
        }
      };

  /**
   * Gets the message string from a command value
   *
   * @param cmd  the command value
   * @return     the message string
   */
  public static String from(int cmd) {
    List<String> names = MESSAGE_INDEX.get().get(cmd);
    if (names != null && names.size() == 1) {
      return names.get(0);
    }

    return Integer.valueOf(cmd).toString();
  }

  private static final LazySupplier<Map<Integer, List<String>>> DISCONNECT_REASON_INDEX =
      new LazySupplier<Map<Integer, List<String>>>() {
        @Override
        protected Map<Integer, List<String>> initialize() {
          return invertFields(f -> f.getName().startsWith("SSH_DISCONNECT_"));
        }
      };

  /**
   * Gets the disconnect reason from a code value
   *
   * @param code  the reason code
   * @return      the reason string
   */
  public static String disconnectReason(int code) {
    return DISCONNECT_REASON_INDEX.get().get(code).get(0);
  }
}
