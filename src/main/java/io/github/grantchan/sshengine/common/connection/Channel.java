package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.IdHolder;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.netty.buffer.ByteBuf;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This interface represents the SSH channel with basic functions.
 */
public interface Channel extends IdHolder, SessionHolder, Closeable {

  /** Channel mapper: Channel identifier(as key) -> Channel object(as value) */
  Map<Integer, Channel> channels = new ConcurrentHashMap<>();

  /** Channel Id generator - generates channel Id in a atomic and sequential way */
  AtomicInteger idGenerator = new AtomicInteger(0);

  /**
   * Returns a registered channel that matches the given ID
   *
   * <p>
   *   The ID is used to identify a specific channel  which comes from the return value of
   *   {@link #register(Channel)} method.
   * </p>
   *
   * @param id the channel ID represents the channel to get
   * @return the channel which the ID represents, if not found, returns NULL
   *
   * @see #register(Channel)
   */
  static Channel get(int id) {
    return channels.get(id);
  }

  /**
   * Returns a group of channel objects which holding the given session.
   *
   * <p>
   *   As long as channel class is extended from SessionHolder, multiple channels might be
   *   associated with a same session, this function returns those Channel objects sharing the same
   *   session.
   * </p>
   *
   * @param session The session is associated by channels in order to find out
   * @return a channel collection holding the given session
   */
  static Collection<Channel> find(AbstractSession session) {
    return SessionHolder.find(channels.values(), session);
  }

  @Override
  int getId();

  int getPeerId();

  /**
   * Registers a given channel
   *
   * <p>
   *   This method should be called when the channel is newly created, so that the channel will be
   *   put into the mapper cache, where the object can be retrieved from by the identifier - the
   *   return value
   * </p>
   *
   * @param channel the channel to register
   * @return the integer can identify the channel object successfully registered
   *
   * @see #unRegister(int)
   */
  default int register(Channel channel) {
    int id = idGenerator.getAndIncrement();

    channels.put(id, channel);

    return id;
  }

  /**
   * Unregisters a channel that has already been registered
   *
   * <p>
   *   This function removes a registered channel from the channel cache, where it'll no longer be
   *   able to find or get from
   * </p>
   *
   * @param id the registered channel Id
   *
   * @see #register(Channel)
   */
  default void unRegister(int id) {
    channels.remove(id);
  }

  /**
   * Open this channel
   *
   * @throws SshChannelException when having trouble registering this channel, or unable to response
   *         client
   */
  void open() throws SshChannelException;

  /**
   * Close this channel
   */
  void close() throws IOException;

  /**
   * @return {@code true} if the channel is open, otherwise {@code false}
   */
  boolean isOpen();

  /**
   * @return the local window using by this channel
   */
  Window getLocalWindow();

  /**
   * @return the remote window using by this channel
   */
  Window getRemoteWindow();

  void handleEof(ByteBuf req) throws IOException;

  void handleClose(ByteBuf req) throws IOException;
}
