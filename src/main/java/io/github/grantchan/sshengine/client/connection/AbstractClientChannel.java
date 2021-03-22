package io.github.grantchan.sshengine.client.connection;

import io.github.grantchan.sshengine.arch.SshConstant;
import io.github.grantchan.sshengine.client.ClientSession;
import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.connection.SshChannelException;
import io.github.grantchan.sshengine.common.connection.Window;
import io.github.grantchan.sshengine.server.connection.ChannelInputStream;
import io.github.grantchan.sshengine.server.connection.ChannelOutputStream;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

public abstract class AbstractClientChannel extends AbstractLogger implements ClientChannel {

  /** Current state of this channel, initially closed */
  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  /** Channel identifier */
  private int id;

  /** The channel identifier used when talking to remote peer */
  private int peerId;

  /** The session that this channel belongs to */
  private final ClientSession session;

  /** Local and remote windows */
  private final Window localWnd = new Window(this, "client/local");
  private Window remoteWnd;

  /**
   * The future object used by creator of this object, usually the session, to indicate the
   * completeness of the opening process
   */
  private CompletableFuture<ClientChannel> openFuture;

  /**
   * The input stream, eg. System.in, where the data inside will be diverted/transmitted to the
   * output stream of this channel
   */
  protected InputStream in;
  /**
   * The output stream, eg. System.out, receives data from the input stream of this channel. If
   * it's not assigned by the user, doOpen(), by default, will set it as a new ChannelOutputStream,
   * where the other side of which is a ChannelInputStream - chIn, created at the same time, that
   * binds the local window, can shink the window and pipe the data to the user.
   */
  protected OutputStream out;
  /**
   * Like the {@code out}, this output stream, eg. System.err, receives data from the error stream
   * of this channel only when extended data is available. If it's not assigned by the user,
   * doOpen(), by default, will set it as a new ChannelOutputStream, where the other side of which
   * is a ChannelInputStream - chErr, created at the same time, that binds the local window, can
   * shink the window and pipe the extended data to the user.
   */
  protected OutputStream err;

  /** Input stream that wraps up the input of this channel */
  protected ChannelInputStream chIn;
  /**
   * Output stream that wraps up the output of this channel, it sends the actual channel data via
   * the {@link io.github.grantchan.sshengine.arch.SshMessage#SSH_MSG_CHANNEL_DATA message
   */
  protected final ChannelOutputStream chOut = new ChannelOutputStream(this, false);
  /**
   * Error stream that wraps up the error output of this channel, it only available when extended
   * data is supported.
   */
  protected ChannelInputStream chErr;

  private BiConsumer<State, ? super Throwable> eventListener;

  public AbstractClientChannel(ClientSession session) {
    this.session = session;
  }

  /**
   * @return the channel identifier
   */
  @Override
  public int getId() {
    return id;
  }

  /**
   * @return the channel identifier of remote side
   */
  @Override
  public int getPeerId() {
    return peerId;
  }

  /**
   * @return the session that this channel belongs to
   */
  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public abstract String getType();

  @Override
  public void setIn(InputStream in) {
    this.in = in;
  }

  @Override
  public void setOut(OutputStream out) {
    this.out = out;
  }

  @Override
  public void setErr(OutputStream err) {
    this.err = err;
  }

  @Override
  public CompletableFuture<ClientChannel> open() throws SshChannelException {
    openFuture = new CompletableFuture<>();

    this.id = register(this);

    logger.debug("{} Channel is registered.", this);

    long wndSize = localWnd.getMaxSize();
    int pkgSize = localWnd.getPacketSize();

    Optional<BiConsumer<State, ? super Throwable>> listener = Optional.ofNullable(eventListener);

    session.sendChannelOpen(getType(), id, (int)wndSize, pkgSize)
           .addListener(l -> {
             Throwable cause = l.cause();
             if (cause != null) {
               openFuture.completeExceptionally(cause);

               listener.ifPresent(el -> el.accept(State.OPENED, cause));

               setState(State.OPENED);
             } else if (l.isCancelled()) {
               openFuture.cancel(true);
             } else {
               listener.ifPresent(el -> el.accept(State.OPENED, null));

               setState(State.OPENED);
             }
           });

    return openFuture;
  }

  @Override
  public boolean isOpen() {
    return getState() == State.OPENED;
  }

  /**
   * Close a channel synchronously
   *
   * @throws IOException If failed to close the channel
   */
  @Override
  public void close() throws IOException {
    setState(State.CLOSING);

    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }

    Optional<BiConsumer<State, ? super Throwable>> listener = Optional.ofNullable(eventListener);

    setState(State.CLOSING);

    try {
      doClose();

      setState(State.CLOSED);

      listener.ifPresent(el -> el.accept(getState(), null));
    } catch (IOException e){
      logger.error("{} Error happened when closing channel. {}", this, e.getMessage());

      setState(State.CLOSED);

      listener.ifPresent(el -> el.accept(getState(), e));
    } finally {
      localWnd.close();
      Optional.ofNullable(remoteWnd).ifPresent(Window::close);

      unRegister(id);  // In a session, once the channel is closed, its id will never be used again

      logger.debug("{} channel is unregistered.", this);
    }
  }

  @Override
  public Window getLocalWindow() {
    return localWnd;
  }

  @Override
  public Window getRemoteWindow() {
    return remoteWnd;
  }

  @Override
  public void handleEof(ByteBuf req) {
    if (openFuture != null && !openFuture.isDone()) {
      openFuture.complete(this);
    }
  }

  @Override
  public void handleClose(ByteBuf req) throws IOException {
    logger.debug("{} Channel received close request.", this);

    close();
  }

  @Override
  public void handleOpenConfirmation(ByteBuf req) {
    peerId = req.readInt();

    int rWndSize = req.readInt();
    int rPkSize = req.readInt();

    logger.debug("{} Received channel open confirmation. peer id={}, window size={}, " +
        "packet size={}", this, peerId, rWndSize, rPkSize);

    if (rPkSize >= Integer.MAX_VALUE) {
      throw new IllegalArgumentException("Remote window size (" + rPkSize + ") is beyond the " +
          "maximum value");
    }

    remoteWnd = new Window(this, "client/remote", rWndSize, rPkSize);

    try {
      doOpen();
    } catch (IOException e) {
      openFuture.completeExceptionally(e);

      return;
    }

    openFuture.complete(this);
  }

  @Override
  public void handleOpenFailure(ByteBuf req) {
    int reason = req.readInt();
    String msg = ByteBufIo.readUtf8(req);
    String lang = ByteBufIo.readUtf8(req);

    logger.debug("{} Failed to open channel, rejected by server. reason={}, message={}, lang={}",
        this, reason, msg, lang);

    Throwable ex = new SshChannelException("Unable to open channel:" + id + ", reason:" + reason +
        ", message:" + msg);
    openFuture.completeExceptionally(ex);

    try {
      close();
    } catch (IOException e) { // must catch exception here, unless we want to disconnect this
                              // whole session.
      logger.warn("{} Failed to open channel.", this);
    } finally {
      localWnd.close();

      unRegister(id);

      logger.debug("{} Channel is unregistered.", this);
    }
  }

  @Override
  public void handleData(ByteBuf req) throws IOException {
    /*
     * byte      SSH_MSG_CHANNEL_DATA
     * uint32    recipient channel
     * string    data
     *
     * https://tools.ietf.org/html/rfc4254#section-5.2
     */
    byte[] data = ByteBufIo.readBytes(req);
    logger.debug("{} SSH_MSG_CHANNEL_DATA, len = {}", this, data.length);

    if (isOpen() && out != null) {
      out.write(data);
      out.flush();

      Optional.ofNullable(chIn).ifPresent(c -> localWnd.consume(data.length));
      return;
    }

    logger.debug("{} The channel is not open, handleData ignored", this);
  }

  @Override
  public void handleExtendedData(ByteBuf req) throws IOException {
    /*
     * Currently, only the following type is defined.  Note that the value
     * for the 'data_type_code' is given in decimal format for readability,
     * but the values are actually uint32 values.
     *
     *             Symbolic name                  data_type_code
     *             -------------                  --------------
     *           SSH_EXTENDED_DATA_STDERR               1
     *
     * https://tools.ietf.org/html/rfc4254#section-5.2
     */
    int code = req.readInt();
    if (code != SshConstant.SSH_EXTENDED_DATA_STDERR) {

      // respond SSH_MSG_CHANNEL_FAILURE
      return;
    }

    /*
     * byte      SSH_MSG_CHANNEL_EXTENDED_DATA
     * uint32    recipient channel
     * uint32    data_type_code
     * string    data
     *
     * https://tools.ietf.org/html/rfc4254#section-5.2
     */
    byte[] data = ByteBufIo.readBytes(req);
    logger.debug("{} SSH_MSG_CHANNEL_EXTENDED_DATA, len = {}", this, data.length);

    if (isOpen() && out != null) {
      out.write(data);
      out.flush();

      Optional.ofNullable(chIn).ifPresent(c -> localWnd.consume(data.length));

      return;
    }

    logger.debug("{} The channel is not open, handleExtendedData ignored", this);
  }

  protected abstract void doOpen() throws IOException;

  protected abstract void doClose() throws IOException;

  @Override
  public State getState() {
    return state.get();
  }

  @Override
  public void setState(State state) {
    this.state.set(state);
  }

  @Override
  public void whenStateChanged(BiConsumer<State, ? super Throwable> listener) {
    this.eventListener = listener;
  }

  @Override
  public String toString() {
    return "[id=" + getId() + ", peer id=" + getPeerId() + ", session=" + session + "]";
  }
}
