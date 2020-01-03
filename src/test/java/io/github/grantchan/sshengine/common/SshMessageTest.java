package io.github.grantchan.sshengine.common;

import io.github.grantchan.sshengine.arch.SshMessage;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SshMessageTest {

  /**
   * Tests getting SSH message string from its ID by calling {@link SshMessage#from(int)}, the
   * following messages are not included:
   *    SSH_MSG_KEXDH_INIT
   *    SSH_MSG_KEXDH_REPLY
   *    SSH_MSG_KEX_DH_GEX_REQUEST_OLD
   *    SSH_MSG_KEX_DH_GEX_GROUP
   * since their IDs are ambiguous.
   *
   * @see #whenGetNameFromDubiousMessage_shouldReturnID()
   */
  @Test
  public void whenGetNameFromUniqueMessage_shouldReturnNameString() {
    assertEquals("SSH_MSG_DISCONNECT", SshMessage.from(SshMessage.SSH_MSG_DISCONNECT));
    assertEquals("SSH_MSG_IGNORE", SshMessage.from(SshMessage.SSH_MSG_IGNORE));
    assertEquals("SSH_MSG_UNIMPLEMENTED", SshMessage.from(SshMessage.SSH_MSG_UNIMPLEMENTED));
    assertEquals("SSH_MSG_DEBUG", SshMessage.from(SshMessage.SSH_MSG_DEBUG));
    assertEquals("SSH_MSG_SERVICE_REQUEST", SshMessage.from(SshMessage.SSH_MSG_SERVICE_REQUEST));
    assertEquals("SSH_MSG_SERVICE_ACCEPT", SshMessage.from(SshMessage.SSH_MSG_SERVICE_ACCEPT));
    assertEquals("SSH_MSG_KEXINIT", SshMessage.from(SshMessage.SSH_MSG_KEXINIT));
    assertEquals("SSH_MSG_NEWKEYS", SshMessage.from(SshMessage.SSH_MSG_NEWKEYS));
    assertEquals("SSH_MSG_USERAUTH_REQUEST", SshMessage.from(SshMessage.SSH_MSG_USERAUTH_REQUEST));
    assertEquals("SSH_MSG_USERAUTH_FAILURE", SshMessage.from(SshMessage.SSH_MSG_USERAUTH_FAILURE));
    assertEquals("SSH_MSG_USERAUTH_SUCCESS", SshMessage.from(SshMessage.SSH_MSG_USERAUTH_SUCCESS));
    assertEquals("SSH_MSG_USERAUTH_BANNER", SshMessage.from(SshMessage.SSH_MSG_USERAUTH_BANNER));
    assertEquals("SSH_MSG_USERAUTH_PK_OK", SshMessage.from(SshMessage.SSH_MSG_USERAUTH_PK_OK));
    assertEquals("SSH_MSG_GLOBAL_REQUEST", SshMessage.from(SshMessage.SSH_MSG_GLOBAL_REQUEST));
    assertEquals("SSH_MSG_REQUEST_SUCCESS", SshMessage.from(SshMessage.SSH_MSG_REQUEST_SUCCESS));
    assertEquals("SSH_MSG_REQUEST_FAILURE", SshMessage.from(SshMessage.SSH_MSG_REQUEST_FAILURE));
    assertEquals("SSH_MSG_CHANNEL_OPEN", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_OPEN));
    assertEquals("SSH_MSG_CHANNEL_OPEN_CONFIRMATION", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    assertEquals("SSH_MSG_CHANNEL_OPEN_FAILURE", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_OPEN_FAILURE));
    assertEquals("SSH_MSG_CHANNEL_WINDOW_ADJUST", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_WINDOW_ADJUST));
    assertEquals("SSH_MSG_CHANNEL_DATA", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_DATA));
    assertEquals("SSH_MSG_CHANNEL_EXTENDED_DATA", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_EXTENDED_DATA));
    assertEquals("SSH_MSG_CHANNEL_EOF", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_EOF));
    assertEquals("SSH_MSG_CHANNEL_CLOSE", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_CLOSE));
    assertEquals("SSH_MSG_CHANNEL_REQUEST", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_REQUEST));
    assertEquals("SSH_MSG_CHANNEL_SUCCESS", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_SUCCESS));
    assertEquals("SSH_MSG_CHANNEL_FAILURE", SshMessage.from(SshMessage.SSH_MSG_CHANNEL_FAILURE));

    assertEquals("SSH_MSG_KEX_DH_GEX_INIT", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_INIT));
    assertEquals("SSH_MSG_KEX_DH_GEX_REPLY", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REPLY));
    assertEquals("SSH_MSG_KEX_DH_GEX_REQUEST", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST));
  }

  /**
   * Tests getting ambiguous SSH message string, of which its ID is not unique - represents more
   * than two SSH messages, by calling {@link SshMessage#from(int)}
   *
   * @see #whenGetNameFromUniqueMessage_shouldReturnNameString()
   */
  @Test
  public void whenGetNameFromDubiousMessage_shouldReturnID() {
    assertEquals("30", SshMessage.from(SshMessage.SSH_MSG_KEXDH_INIT));
    assertEquals("31", SshMessage.from(SshMessage.SSH_MSG_KEXDH_REPLY));
    assertEquals("30", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST_OLD));
    assertEquals("31", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_GROUP));
  }

  /**
   * Tests getting SSH disconnect reason string from its ID by calling {@link SshMessage#disconnectReason(int)}
   */
  @Test
  public void testDisconnectReason() {
    assertEquals("SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT));
    assertEquals("SSH_DISCONNECT_PROTOCOL_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR));
    assertEquals("SSH_DISCONNECT_KEY_EXCHANGE_FAILED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED));
    assertEquals("SSH_DISCONNECT_RESERVED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_RESERVED));
    assertEquals("SSH_DISCONNECT_MAC_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_MAC_ERROR));
    assertEquals("SSH_DISCONNECT_COMPRESSION_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_COMPRESSION_ERROR));
    assertEquals("SSH_DISCONNECT_SERVICE_NOT_AVAILABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE));
    assertEquals("SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED));
    assertEquals("SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE));
    assertEquals("SSH_DISCONNECT_CONNECTION_LOST", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_CONNECTION_LOST));
    assertEquals("SSH_DISCONNECT_BY_APPLICATION", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_BY_APPLICATION));
    assertEquals("SSH_DISCONNECT_TOO_MANY_CONNECTIONS", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_TOO_MANY_CONNECTIONS));
    assertEquals("SSH_DISCONNECT_AUTH_CANCELLED_BY_USER", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_AUTH_CANCELLED_BY_USER));
    assertEquals("SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE));
    assertEquals("SSH_DISCONNECT_ILLEGAL_USER_NAME", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_ILLEGAL_USER_NAME));
  }
}