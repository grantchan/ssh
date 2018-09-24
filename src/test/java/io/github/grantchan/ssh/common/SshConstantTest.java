package io.github.grantchan.ssh.common;

import org.junit.Test;

import static org.junit.Assert.*;

public class SshConstantTest {

  @Test
  public void testMessageName() throws Exception {
    assertEquals("SSH_MSG_DISCONNECT", SshConstant.messageName(SshConstant.SSH_MSG_DISCONNECT));
    assertEquals("SSH_MSG_SERVICE_REQUEST", SshConstant.messageName(SshConstant.SSH_MSG_SERVICE_REQUEST));
    assertEquals("SSH_MSG_SERVICE_ACCEPT", SshConstant.messageName(SshConstant.SSH_MSG_SERVICE_ACCEPT));
    assertEquals("SSH_MSG_KEXINIT", SshConstant.messageName(SshConstant.SSH_MSG_KEXINIT));
    assertEquals("SSH_MSG_NEWKEYS", SshConstant.messageName(SshConstant.SSH_MSG_NEWKEYS));
    assertEquals("SSH_MSG_KEX_DH_GEX_REQUEST_OLD", SshConstant.messageName(SshConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD));
    assertEquals("SSH_MSG_KEX_DH_GEX_GROUP", SshConstant.messageName(SshConstant.SSH_MSG_KEX_DH_GEX_GROUP));
    assertEquals("SSH_MSG_KEX_DH_GEX_INIT", SshConstant.messageName(SshConstant.SSH_MSG_KEX_DH_GEX_INIT));
    assertEquals("SSH_MSG_KEX_DH_GEX_REPLY", SshConstant.messageName(SshConstant.SSH_MSG_KEX_DH_GEX_REPLY));
    assertEquals("SSH_MSG_KEX_DH_GEX_REQUEST", SshConstant.messageName(SshConstant.SSH_MSG_KEX_DH_GEX_REQUEST));
  }

  @Test
  public void testDisconnectReason() throws Exception {
    assertEquals("SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT   ));
    assertEquals("SSH_DISCONNECT_PROTOCOL_ERROR", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_PROTOCOL_ERROR                ));
    assertEquals("SSH_DISCONNECT_KEY_EXCHANGE_FAILED", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_KEY_EXCHANGE_FAILED           ));
    assertEquals("SSH_DISCONNECT_RESERVED", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_RESERVED                      ));
    assertEquals("SSH_DISCONNECT_MAC_ERROR", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_MAC_ERROR                     ));
    assertEquals("SSH_DISCONNECT_COMPRESSION_ERROR", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_COMPRESSION_ERROR             ));
    assertEquals("SSH_DISCONNECT_SERVICE_NOT_AVAILABLE", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE         ));
    assertEquals("SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED));
    assertEquals("SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE       ));
    assertEquals("SSH_DISCONNECT_CONNECTION_LOST", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_CONNECTION_LOST               ));
    assertEquals("SSH_DISCONNECT_BY_APPLICATION", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_BY_APPLICATION                ));
    assertEquals("SSH_DISCONNECT_TOO_MANY_CONNECTIONS", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_TOO_MANY_CONNECTIONS          ));
    assertEquals("SSH_DISCONNECT_AUTH_CANCELLED_BY_USER", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_AUTH_CANCELLED_BY_USER        ));
    assertEquals("SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE));
    assertEquals("SSH_DISCONNECT_ILLEGAL_USER_NAME", SshConstant.disconnectReason(SshConstant.SSH_DISCONNECT_ILLEGAL_USER_NAME             ));
  }
}