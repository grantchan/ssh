package io.github.grantchan.sshengine.common.transport.handler;

import io.github.grantchan.sshengine.common.transport.compression.Compression;
import io.github.grantchan.sshengine.util.buffer.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

import static io.github.grantchan.sshengine.arch.SshConstant.SSH_PACKET_HEADER_LENGTH;

public interface PacketEncoder extends SessionHolder {

  Logger logger = LoggerFactory.getLogger(PacketEncoder.class);

  SecureRandom rand = new SecureRandom();

  Cipher getCipher();

  int getCipherSize();

  Mac getMac();

  int getMacSize();

  int getDefMacSize();

  Compression getCompression();

  default ByteBuf encode(ByteBuf msg, AtomicLong seq) {
    int len = msg.readableBytes();
    int off = msg.readerIndex() - SSH_PACKET_HEADER_LENGTH;

    Compression comp = getCompression();
    if (comp != null && getSession().isAuthed() && len > 0) {
      byte[] plain = new byte[len];
      msg.readBytes(plain);

      msg.readerIndex(SSH_PACKET_HEADER_LENGTH);
      msg.writerIndex(SSH_PACKET_HEADER_LENGTH);

      byte[] zipped = comp.compress(plain);
      logger.debug("[{}] Compressed packet: ({} -> {} bytes)", getSession(), plain.length,
          zipped.length);

      msg.writeBytes(zipped);
      len = msg.readableBytes();
    }

    // Calculate padding length
    int bsize  = getCipherSize();
    int oldLen = len;
    len += SSH_PACKET_HEADER_LENGTH;
    int pad = (-len) & (bsize - 1);
    if (pad < bsize) {
      pad += bsize;
    }
    len += pad - 4;

    // Write 5 header bytes
    msg.readerIndex(0);
    msg.writerIndex(off);
    msg.writeInt(len);
    msg.writeByte(pad);

    // Fill padding
    msg.writerIndex(off + SSH_PACKET_HEADER_LENGTH + oldLen);
    byte[] padding = new byte[pad];
    rand.nextBytes(padding);
    msg.writeBytes(padding);

    byte[] packet = new byte[msg.readableBytes()];
    msg.getBytes(off, packet);

    Mac mac = getMac();
    if (mac != null) {
      int macSize = getMacSize();
      mac.update(Bytes.htonl(seq.get()));
      mac.update(packet);
      byte[] tmp = mac.doFinal();
      if (macSize != getDefMacSize()) {
        msg.writeBytes(tmp, 0, macSize);
      } else {
        msg.writeBytes(tmp);
      }
    }

    Cipher cipher = getCipher();
    if (cipher != null) {
      StringBuilder sb = new StringBuilder();
      ByteBufUtil.appendPrettyHexDump(sb, msg);
      logger.debug("[{}] Packet before encryption: \n{}", getSession(), sb.toString());

      byte[] tmp = new byte[len + 4 - off];
      msg.getBytes(off, tmp);

      msg.setBytes(off, cipher.update(tmp));
    }

    seq.set(seq.incrementAndGet() & 0xffffffffL);

    return msg;
  }
}
