package io.github.grantchan.ssh.common.transport.handler;

import io.github.grantchan.ssh.arch.SshConstant;
import io.github.grantchan.ssh.arch.SshMessage;
import io.github.grantchan.ssh.client.ClientSession;
import io.github.grantchan.ssh.common.transport.cipher.CipherFactories;
import io.github.grantchan.ssh.server.ServerSession;
import io.github.grantchan.ssh.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.logging.LoggingHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PacketCodecTest {

  private EmbeddedChannel clientChannel, serverChannel;
  private ClientSession clientSession;
  private ServerSession serverSession;

  private final Random rand = new SecureRandom();

  @Before
  public void setUp() {
    // Client as sender to send encoded message
    clientChannel = new EmbeddedChannel(new LoggingHandler());
    ChannelHandlerContext clientCtx = clientChannel.pipeline().context(LoggingHandler.class);
    clientSession = new ClientSession(clientCtx);

    clientChannel.pipeline()
        .addLast(new io.github.grantchan.ssh.client.transport.handler.PacketEncoder(clientSession));

    // Server as receiver to decode message
    serverChannel = new EmbeddedChannel(new LoggingHandler());
    ChannelHandlerContext serverCtx = clientChannel.pipeline().context(LoggingHandler.class);
    serverSession = new ServerSession(serverCtx);

    serverChannel.pipeline()
        .addFirst(new io.github.grantchan.ssh.server.transport.handler.PacketDecoder(serverSession));
  }

  @After
  public void tearDown() {
    serverChannel.finish();
    clientChannel.finish();
  }

  @Test
  public void whenSendPrimeNumberInKexMessage_shouldBeDecodedByRecipient() {
    // Construct a SSH_MSG_KEXDH_INIT message
    ByteBuf msg = Unpooled.buffer();
    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(SshMessage.SSH_MSG_KEXDH_INIT);

    BigInteger expectedPrime = BigInteger.probablePrime(1024, rand);
    ByteBufIo.writeMpInt(msg, expectedPrime);

    // After writing the message plaintext to the channel which contains packet encoder, expect the
    // encoded result to be readable from the outbound pipeline
    assertTrue(clientChannel.writeOutbound(msg));
    // Expect only one result from the outbound pipeline
    assertEquals(1, clientChannel.outboundMessages().size());

    ByteBuf encodedMsg = clientChannel.readOutbound();

    // After writing the encoded message to the channel which contains packet decoder, expect the
    // decoded result to be readable from the inbound pipeline
    assertTrue(serverChannel.writeInbound(encodedMsg));
    // Expect only one result from the inbound pipeline
    assertEquals(1, serverChannel.inboundMessages().size());

    ByteBuf decodedMsg = serverChannel.readInbound();

    assertEquals(SshMessage.SSH_MSG_KEXDH_INIT, decodedMsg.readByte() & 0xFF);
    assertEquals(expectedPrime, ByteBufIo.readMpInt(decodedMsg));
  }

  @Test
  public void whenSendEncryptedMessage_shouldBeDecryptedByRecipient() {
    // Construct a SSH_MSG_DEBUG message
    ByteBuf msg = Unpooled.buffer();
    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(SshMessage.SSH_MSG_DEBUG);

    String expectedString = "a quick movement of the enemy will jeopardize six gunboats";
    ByteBufIo.writeUtf8(msg, expectedString);

    CipherFactories cf = CipherFactories.from("aes256-ctr");

    byte[] secretKey = new byte[cf.getBlkSize()];
    rand.nextBytes(secretKey);

    byte[] iv = new byte[cf.getBlkSize()];
    rand.nextBytes(iv);

    // Set up cipher setting in client session
    Cipher clientC2sCip = cf.create(secretKey, iv, Cipher.ENCRYPT_MODE);
    clientSession.setC2sCipher(clientC2sCip);
    clientSession.setC2sCipherSize(cf.getIvSize());

    // After writing encrypted message to the channel, in which the session in the packet encoder
    // has cipher setting, expect the encrypted result to be readable from the outbound pipeline
    assertTrue(clientChannel.writeOutbound(msg));
    // Expect only one result from the outbound pipeline
    assertEquals(1, clientChannel.outboundMessages().size());

    ByteBuf encryptedMsg = clientChannel.readOutbound();

    // Set up cipher setting in server session
    Cipher serverC2sCip = cf.create(secretKey, iv, Cipher.DECRYPT_MODE);
    serverSession.setC2sCipher(serverC2sCip);
    serverSession.setC2sCipherSize(cf.getIvSize());

    // After writing encrypted message to the channel, in which the session in the packet decoder
    // has cipher setting, expect the decrypted result to be readable from the inbound pipeline
    assertTrue(serverChannel.writeInbound(encryptedMsg));
    // Expect only one result from the inbound pipeline
    assertEquals(1, serverChannel.inboundMessages().size());

    ByteBuf decryptedMsg = serverChannel.readInbound();

    assertEquals(SshMessage.SSH_MSG_DEBUG, decryptedMsg.readByte() & 0xFF);
    assertEquals(expectedString, ByteBufIo.readUtf8(decryptedMsg));
  }
}