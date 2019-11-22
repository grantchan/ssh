package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.Closeable;
import io.github.grantchan.sshengine.common.IdHolder;
import io.netty.buffer.ByteBuf;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public interface Channel extends Closeable, IdHolder {

  // Channel mapper: Channel identifier(as key) -> Channel object(as value)
  Map<Integer, Channel> channels = new ConcurrentHashMap<>();

  // Channel Id generator - generates channel Id in a atomic and sequential way
  AtomicInteger idGenerator = new AtomicInteger(0);

  static Channel get(int id) {
    return channels.get(id);
  }

  /**
   * Put a channel into the channel mapper.
   * This method should be called when the channel is newly created.
   *
   * @return the integer can identify the channel object successfully registered
   */
  default int register() {
    int id = idGenerator.getAndIncrement();

    channels.put(id, this);

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

  void handleRequest(ByteBuf req);
}
