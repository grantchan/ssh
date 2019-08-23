package io.github.grantchan.SshEngine.common.transport.handler;

import io.github.grantchan.SshEngine.arch.SshMessage;
import io.github.grantchan.SshEngine.common.SshException;
import io.github.grantchan.SshEngine.server.ServerSession;
import io.github.grantchan.SshEngine.server.transport.handler.ServerPacketDecoder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PacketDecoderTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void whenPacketSizeIsTooSmall_shouldThrowProtocolError() throws Exception {
    thrown.expect(SshException.class);

    thrown.expectMessage("Invalid packet length: 0");
    thrown.expect(hasProperty("disconnectReason"));
    thrown.expect(hasProperty("disconnectReason", is(SshMessage.SSH_DISCONNECT_PROTOCOL_ERROR)));

    ServerSession session = Mockito.mock(ServerSession.class);
    Mockito.when(session.getC2sCipherSize()).thenReturn(8);
    Mockito.when(session.createBuffer()).thenReturn(Unpooled.buffer());

    ChannelHandlerContext ctx = Mockito.mock(ChannelHandlerContext.class);

    ByteBuf packet = Unpooled.buffer();
    packet.writeBytes(new byte[9]);

    ServerPacketDecoder decoder = new ServerPacketDecoder(session);
    decoder.handlerAdded(ctx);

    decoder.channelRead(ctx, packet);
  }
}