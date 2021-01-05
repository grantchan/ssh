package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.server.ServerSession;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PacketDecoderTest {

  @Test
  public void whenPacketSizeIsTooSmall_shouldThrowProtocolError() {
    AbstractSession session = Mockito.mock(ServerSession.class);
    Mockito.when(session.getInCipherBlkSize()).thenReturn(8);
    Mockito.when(session.createBuffer()).thenReturn(Unpooled.buffer());

    ChannelHandlerContext ctx = Mockito.mock(ChannelHandlerContext.class);

    ByteBuf packet = Unpooled.buffer();
    packet.writeBytes(new byte[9]);

    PacketDecoder decoder = new PacketDecoder(session);
    decoder.handlerAdded(ctx);

    SshException e = assertThrows(SshException.class, () -> decoder.channelRead(ctx, packet));

    assertEquals(e.getMessage(), "Invalid packet length: 0");
    assertThat(e, hasProperty("reason", is(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR)));
  }
}