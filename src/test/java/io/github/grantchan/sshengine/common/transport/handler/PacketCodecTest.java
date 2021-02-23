package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.arch.SshMessage;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.SshException;
import io.github.grantchan.sshengine.common.transport.cipher.CipherFactories;
import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.common.transport.compression.CompressionFactories;
import io.github.grantchan.sshengine.common.transport.mac.MacFactories;
import io.github.grantchan.sshengine.server.ServerSession;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.logging.LoggingHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import static io.github.grantchan.sshengine.common.transport.cipher.CipherFactories.aes256cbc;
import static io.github.grantchan.sshengine.common.transport.cipher.CipherFactories.aes256ctr;
import static io.github.grantchan.sshengine.common.transport.compression.CompressionFactories.delayedZLib;
import static io.github.grantchan.sshengine.common.transport.mac.MacFactories.hmacsha1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class PacketCodecTest {
  private EmbeddedChannel clientChannel, serverChannel;

  private final Random rand = new SecureRandom();

  @Parameter(0)
  public CipherFactories cipFactories;
  @Parameter(1)
  public MacFactories macFactories;
  @Parameter(2)
  public CompressionFactories compFactories;

  /** Permutation of cipher, MAC, compression */
  @Parameters(name = "{index}: Cipher={0}, MAC={1}, Compression={2}")
  public static Collection<Object[]> parameters() {
    return Arrays.asList(new Object[][] {
        {null,      null,     null},
        {aes256cbc, null,     null},
        {aes256ctr, null,     null},
        {null,      hmacsha1, null},
        {null,      null,     delayedZLib},
        {aes256cbc, hmacsha1, null},
        {aes256ctr, hmacsha1, null},
        {aes256cbc, null,     delayedZLib},
        {aes256ctr, null,     delayedZLib},
        {null,      hmacsha1, delayedZLib},
        {aes256cbc, hmacsha1, delayedZLib},
        {aes256ctr, hmacsha1, delayedZLib}
    });
  }

  /**
   * Constructs:
   * a client channel as sender to encode the message packet,
   * a server channel as receiver to decode the received packet,
   *
   * in which the cipher, MAC, compression are created by different parameter permutations
   */
  @Before
  public void setUp() throws SshException {
    // Client as sender to send encoded message
    clientChannel = new EmbeddedChannel(new LoggingHandler());
    ClientSession clientSession = new ClientSession(clientChannel);
    clientChannel.pipeline().addLast(new PacketEncoder(clientSession));

    // Server as receiver to decode message
    serverChannel = new EmbeddedChannel(new LoggingHandler());
    ServerSession serverSession = new ServerSession(serverChannel);
    serverChannel.pipeline().addFirst(new PacketDecoder(serverSession));

    if (cipFactories != null) {
      // Set up cipher factory
      byte[] secretKey = new byte[cipFactories.getBlkSize()];
      rand.nextBytes(secretKey);

      byte[] iv = new byte[cipFactories.getBlkSize()];
      rand.nextBytes(iv);

      // Set up cipher setting in client session
      Cipher clientC2sCip = cipFactories.create(secretKey, iv, Cipher.ENCRYPT_MODE);
      clientSession.setOutCipher(clientC2sCip);
      clientSession.setOutCipherBlkSize(cipFactories.getIvSize());

      // Set up cipher setting in server session
      Cipher serverC2sCip = cipFactories.create(secretKey, iv, Cipher.DECRYPT_MODE);
      serverSession.setInCipher(serverC2sCip);
      serverSession.setInCipherBlkSize(cipFactories.getIvSize());
    }

    byte[] macKey;
    if (macFactories != null) {
      // Set up MAC factory
      macKey = new byte[macFactories.getBlkSize()];
      rand.nextBytes(macKey);

      // Set up MAC setting in client session
      Mac clientC2sMac = macFactories.create(macKey);
      clientSession.setOutMac(clientC2sMac);
      clientSession.setOutMacSize(macFactories.getBlkSize());
      clientSession.setOutDefMacSize(macFactories.getDefBlkSize());

      // Setup MAC setting in server session
      Mac serverC2sMac = macFactories.create(macKey);
      serverSession.setInMac(serverC2sMac);
      serverSession.setInMacSize(macFactories.getBlkSize());
      serverSession.setInDefMacSize(macFactories.getDefBlkSize());
    }

    if (compFactories != null) {
      Compression clientComp = compFactories.create();
      clientSession.setOutCompression(clientComp);
      clientSession.setAuthed(true);

      Compression serverComp = compFactories.create();
      serverSession.setInCompression(serverComp);
      serverSession.setAuthed(true);
    }
  }

  @After
  public void tearDown() {
    serverChannel.finish();
    clientChannel.finish();
  }

  /**
   * Test when using different permutation of cipher, MAC, compression, receiver
   * should be able to decipher, decompress, verify (by MAC) the SSH_MSG_DEBUG message.
   */
  @Test
  public void whenMessageSent_shouldBeHandledByRecipient() {
    // Construct a SSH_MSG_DEBUG message
    ByteBuf msg = Unpooled.buffer();
    msg.writerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.readerIndex(SshConstant.SSH_PACKET_HEADER_LENGTH);
    msg.writeByte(SshMessage.SSH_MSG_DEBUG);

    String expectedString = "a quick movement of the enemy will jeopardize six gunboats";
    ByteBufIo.writeUtf8(msg, expectedString);

    // After writing encrypted message to the channel, in which the session in the packet encoder
    // has cipher setting, expect the encrypted result to be readable from the outbound pipeline
    assertTrue(clientChannel.writeOutbound(msg));
    // Expect only one result from the outbound pipeline
    assertEquals(1, clientChannel.outboundMessages().size());

    ByteBuf encodedMsg = clientChannel.readOutbound();

    // After writing encrypted message to the channel, in which the session in the packet decoder
    // has cipher setting, expect the decrypted result to be readable from the inbound pipeline
    assertTrue(serverChannel.writeInbound(encodedMsg));
    // Expect only one result from the inbound pipeline
    assertEquals(1, serverChannel.inboundMessages().size());

    ByteBuf decodedMsg = serverChannel.readInbound();

    assertEquals(SshMessage.SSH_MSG_DEBUG, decodedMsg.readByte() & 0xFF);
    assertEquals(expectedString, ByteBufIo.readUtf8(decodedMsg));
  }
}
