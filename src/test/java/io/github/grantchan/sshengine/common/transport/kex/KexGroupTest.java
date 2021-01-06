package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.transport.kex.ClientDhGroup;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.server.transport.kex.ServerDhGroup;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KexGroupTest {

  @Test
  public void whenMessageIdDoesntMatchExpected_shouldThrowException() throws Exception {

    String expectedMsg = "Invalid key exchange message, expect: SSH_MSG_KEXDH_INIT, actual: 31";

    KexGroup ckg = new ClientDhGroup(null, null, null);
    SshException e = assertThrows(SshException.class,
        () -> ckg.handle(SshMessage.SSH_MSG_KEXDH_REPLY, null));
    assertEquals(expectedMsg, e.getMessage());
    assertThat(e, hasProperty("reason", is(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)));

    KexGroup skg = new ServerDhGroup(null, null, null);
    SshException e1 = assertThrows(SshException.class,
        () -> skg.handle(SshMessage.SSH_MSG_KEXDH_REPLY, null));
    assertEquals(expectedMsg, e1.getMessage());
    assertThat(e1, hasProperty("reason", is(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)));
  }

}