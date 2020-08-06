package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.IdHolder;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public interface Channel extends IdHolder, SessionHolder {

  // Channel mapper: Channel identifier(as key) -> Channel object(as value)
  Map<Integer, Channel> channels = new ConcurrentHashMap<>();

  // Channel Id generator - generates channel Id in a atomic and sequential way
  AtomicInteger idGenerator = new AtomicInteger(0);

  static Channel get(int id) {
    return channels.get(id);
  }

  /**
   * Put a channel into the channel mapper.
   *
   * <p>This method should be called when the channel is newly created.</p>
   *
   * @param channel the channel to register
   * @return the integer can identify the channel object successfully registered
   */
  default int register(Channel channel) {
    int id = idGenerator.getAndIncrement();

    channels.put(id, channel);

    return id;
  }

  /**
   * Remove a registered channel from the channel mapper
   *
   * @param id the registered channel Id
   */
  default void unRegister(int id) {
    channels.remove(id);
  }

  /**
   * Open a channel asynchronously
   *
   * @param peerId Remote channel identifier
   * @param rwndsize Remote window size
   * @param rpksize Remote packet size
   * @return A CompletableFuture object as a handle to the result of the asynchronous open process,
   *         once the process is finish, the result can be accessed by this object.
   */
  CompletableFuture<Boolean> open(int peerId, int rwndsize, int rpksize);

  /**
   * Close asynchronously
   *
   * @return A CompletableFuture object as a handle to the result of the asynchronous close process,
   *         once the process is finish, the result can be accessed by this object.
   */
  CompletableFuture<Boolean> close();

  /**
   * @return {@code true} if the channel is open, otherwise {@code false}
   */
  boolean isOpen();

  /**
   * @return the local window
   */
  Window getLocalWindow();

  /**
   * @return the remote window
   */
  Window getRemoteWindow();

  void handleWindowAdjust(ByteBuf req);

  void handleData(ByteBuf req) throws IOException;

  void handleEof(ByteBuf req) throws IOException;

  void handleClose(ByteBuf req) throws IOException;

  void handleRequest(ByteBuf req) throws IOException;

  static Collection<Channel> find(AbstractSession session) {
    return SessionHolder.find(channels.values(), session);
  }
}
