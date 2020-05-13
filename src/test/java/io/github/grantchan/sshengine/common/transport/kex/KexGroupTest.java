package io.github.grantchan.sshengine.common.transport.kex;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.transport.kex.ClientDhGroup;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.server.transport.kex.ServerDhGroup;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;

import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KexGroupTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void whenMessageIdDoesntMatchExpected_shouldThrowException() throws Exception {
    thrown.expect(SshException.class);

    thrown.expectMessage("Invalid key exchange message, expect: SSH_MSG_KEXDH_INIT, actual: 31");
    thrown.expect(hasProperty("reason"));
    thrown.expect(hasProperty("reason", is(SshMessage.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)));

    new ClientDhGroup(null, null, null).handle(SshMessage.SSH_MSG_KEXDH_REPLY, null);
    new ServerDhGroup(null, null, null).handle(SshMessage.SSH_MSG_KEXDH_REPLY, null);
  }

}