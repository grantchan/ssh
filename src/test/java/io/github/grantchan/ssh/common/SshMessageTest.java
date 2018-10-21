package io.github.grantchan.ssh.common;

import io.github.grantchan.ssh.arch.SshMessage;
import org.junit.Test;

import static org.junit.Assert.*;

public class SshMessageTest {

  @Test
  public void testMessageName() throws Exception {
    assertEquals("SSH_MSG_DISCONNECT", SshMessage.from(SshMessage.SSH_MSG_DISCONNECT));
    assertEquals("SSH_MSG_SERVICE_REQUEST", SshMessage.from(SshMessage.SSH_MSG_SERVICE_REQUEST));
    assertEquals("SSH_MSG_SERVICE_ACCEPT", SshMessage.from(SshMessage.SSH_MSG_SERVICE_ACCEPT));
    assertEquals("SSH_MSG_KEXINIT", SshMessage.from(SshMessage.SSH_MSG_KEXINIT));
    assertEquals("SSH_MSG_NEWKEYS", SshMessage.from(SshMessage.SSH_MSG_NEWKEYS));
    assertEquals("SSH_MSG_KEX_DH_GEX_REQUEST_OLD", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST_OLD));
    assertEquals("SSH_MSG_KEX_DH_GEX_GROUP", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_GROUP));
    assertEquals("SSH_MSG_KEX_DH_GEX_INIT", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_INIT));
    assertEquals("SSH_MSG_KEX_DH_GEX_REPLY", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REPLY));
    assertEquals("SSH_MSG_KEX_DH_GEX_REQUEST", SshMessage.from(SshMessage.SSH_MSG_KEX_DH_GEX_REQUEST));
  }

  @Test
  public void testDisconnectReason() throws Exception {
    assertEquals("SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT   ));
    assertEquals("SSH_DISCONNECT_PROTOCOL_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR                ));
    assertEquals("SSH_DISCONNECT_KEY_EXCHANGE_FAILED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED           ));
    assertEquals("SSH_DISCONNECT_RESERVED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_RESERVED                      ));
    assertEquals("SSH_DISCONNECT_MAC_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_MAC_ERROR                     ));
    assertEquals("SSH_DISCONNECT_COMPRESSION_ERROR", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_COMPRESSION_ERROR             ));
    assertEquals("SSH_DISCONNECT_SERVICE_NOT_AVAILABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE         ));
    assertEquals("SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED));
    assertEquals("SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE       ));
    assertEquals("SSH_DISCONNECT_CONNECTION_LOST", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_CONNECTION_LOST               ));
    assertEquals("SSH_DISCONNECT_BY_APPLICATION", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_BY_APPLICATION                ));
    assertEquals("SSH_DISCONNECT_TOO_MANY_CONNECTIONS", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_TOO_MANY_CONNECTIONS          ));
    assertEquals("SSH_DISCONNECT_AUTH_CANCELLED_BY_USER", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_AUTH_CANCELLED_BY_USER        ));
    assertEquals("SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE));
    assertEquals("SSH_DISCONNECT_ILLEGAL_USER_NAME", SshMessage.disconnectReason(SshMessage.SSH_DISCONNECT_ILLEGAL_USER_NAME             ));
  }
}