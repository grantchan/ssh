package io.github.grantchan.sshengine.common.connection;

import io.github.grantchan.sshengine.common.AbstractLogger;
import io.github.grantchan.sshengine.common.AbstractSession;
import io.github.grantchan.sshengine.common.transport.handler.SessionHolder;
import io.github.grantchan.sshengine.util.buffer.ByteBufIo;
import io.netty.buffer.ByteBuf;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

public abstract class AbstractChannel extends AbstractLogger
                                      implements Channel, SessionHolder {

  // Channel identifier
  private final int id;
  private final AbstractSession session;

  private int peerId;

  // The executor to run open/close tasks in asynchronous mode
  private static final ExecutorService executor = Executors.newFixedThreadPool(3);

  // Channel states
  protected enum State { OPENED, CLOSING, CLOSED }

  // Current state, initially "Closed"
  private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);

  public AbstractChannel(AbstractSession session) {
    this.session = session;

    this.id = register(this);
  }

  /**
   * @return the channel identifier
   */
  @Override
  public int getId() {
    return id;
  }

  @Override
  public AbstractSession getSession() {
    return session;
  }

  @Override
  public CompletableFuture<Boolean> open(int peerId, int rwndsize, int rpksize) {
    CompletableFuture<Boolean> future = new CompletableFuture<>();

    executor.submit(() -> {
      if (state.compareAndSet(State.CLOSED, State.OPENED)) {
        logger.debug("[{}] Channel is being opened...", this);

        try {
          this.peerId = peerId;

          doOpen(rwndsize, rpksize);

          logger.debug("[{}] Channel is opened - {}", this, state.get());

          future.complete(true);
        } catch (Exception e) {
          logger.debug("[{}] Failed to open channel - {}", this, state.get());

          future.complete(false);
        }
      } else {
        logger.debug("[{}] This channel is already opened - {}", this, state.get());

        future.complete(true);
      }
    });
    return future;
  }

  /**
   * Open a channel synchronously
   *
   * @param rwndsize Remote window size
   * @param rpksize Remote packet size
   * @throws Exception If failed to open the channel
   */
  protected void doOpen(int rwndsize, int rpksize) throws Exception {
    state.set(State.OPENED);
  }

  /**
   * Close a channel asynchronously
   */
  @Override
  public CompletableFuture<Boolean> closeGracefully() {
    CompletableFuture<Boolean> future = new CompletableFuture<>();

    executor.submit(() -> {
      if (state.compareAndSet(State.OPENED, State.CLOSING)) {
        logger.debug("[{}] Channel is being closed...", this);

        try {
          doClose();

          logger.debug("[{}] Channel is closed - {}", this, state.get());

          future.complete(true);
        } catch (Exception e) {
          logger.debug("[{}] Failed to close channel - {}", this, state.get());

          future.complete(false);
        }
      } else {
        logger.debug("[{}] This channel is already closed - {}", this, state.get());

        future.complete(true);
      }
    });
    return future;
  }

  /**
   * Close a channel synchronously
   *
   * @throws Exception If failed to close the channel
   */
  protected void doClose() throws Exception {
    unRegister(this.id);  // In a session, once the channel is closed, it'll never be opened again

    state.set(State.CLOSED);
  }

  @Override
  public void handleRequest(ByteBuf req) {

    /*
     * 5.4.  Channel-Specific Requests
     *
     * Many 'channel type' values have extensions that are specific to that
     * particular 'channel type'.  An example is requesting a pty (pseudo
     * terminal) for an interactive session.
     *
     * All channel-specific requests use the following format.
     *
     *    byte      SSH_MSG_CHANNEL_REQUEST
     *    uint32    recipient channel
     *    string    request type in US-ASCII characters only
     *    boolean   want reply
     *    ....      type-specific data follows
     *
     * If 'want reply' is FALSE, no response will be sent to the request.
     * Otherwise, the recipient responds with either
     * SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE, or request-specific
     * continuation messages.  If the request is not recognized or is not
     * supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.
     *
     * This message does not consume window space and can be sent even if no
     * window space is available.  The values of 'request type' are local to
     * each channel type.
     *
     * The client is allowed to send further messages without waiting for
     * the response to the request.
     *
     * 'request type' names follow the DNS extensibility naming convention
     * outlined in [SSH-ARCH] and [SSH-NUMBERS].
     *
     *    byte      SSH_MSG_CHANNEL_SUCCESS
     *    uint32    recipient channel
     *
     *    byte      SSH_MSG_CHANNEL_FAILURE
     *    uint32    recipient channel
     *
     * These messages do not consume window space and can be sent even if no
     * window space is available.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4254#section-5.4">Channel-Specific Requests</a>
     */
    String type = ByteBufIo.readUtf8(req);

    logger.debug("[{}] Received SSH_MSG_CHANNEL_REQUEST. request type:{}", this, type);

    boolean wantReply = req.getBoolean(req.readerIndex());

    boolean ret = false;
    switch (type) {
      case "pty-req":
        ret = handlePtyReq(req);
        break;

      case "shell":
        ret = handleShell(req);
        break;

      default:

    }

    if (wantReply) {
      if (ret) {
        session.replyChannelSuccess(peerId);
      } else {
        session.replyChannelFailure(peerId);
      }
    }
  }

  private boolean handlePtyReq(ByteBuf req) {

    /*
     * 6.2.  Requesting a Pseudo-Terminal
     *
     * A pseudo-terminal can be allocated for the session by sending the
     * following message.
     *
     *    byte      SSH_MSG_CHANNEL_REQUEST
     *    ....      (fields already consumed before getting here)
     *    boolean   want_reply
     *    string    TERM environment variable value (e.g., vt100)
     *    uint32    terminal width, characters (e.g., 80)
     *    uint32    terminal height, rows (e.g., 24)
     *    uint32    terminal width, pixels (e.g., 640)
     *    uint32    terminal height, pixels (e.g., 480)
     *    string    encoded terminal modes
     *
     * The 'encoded terminal modes' are described in Section 8.  Zero
     * dimension parameters MUST be ignored.  The character/row dimensions
     * override the pixel dimensions (when nonzero).  Pixel dimensions refer
     * to the drawable area of the window.
     *
     * The dimension parameters are only informational.
     *
     * The client SHOULD ignore pty requests.
     */
    boolean wantReply = req.readBoolean();
    String term = ByteBufIo.readUtf8(req);
    int termCols = req.readInt();
    int termRows = req.readInt();
    int termWidth = req.readInt();
    int termHeight = req.readInt();
    byte[] modes = ByteBufIo.readBytes(req);

    logger.debug("[{}] Received pty-req request. want reply:{}, terminal:{}, " +
            "terminal columns:{}, terminal rows:{}, terminal width:{}, terminal height:{}",
        this, wantReply, term, termCols, termRows, termWidth, termHeight);

    return true;
  }

  private boolean handleShell(ByteBuf req) {

    /*
     * 6.5.  Starting a Shell or a Command
     *
     * Once the session has been set up, a program is started at the remote
     * end.  The program can be a shell, an application program, or a
     * subsystem with a host-independent name.  Only one of these requests
     * can succeed per channel.
     *
     *    byte      SSH_MSG_CHANNEL_REQUEST
     *    ....      (fields already consumed before getting here)
     *    string    "shell"
     *    boolean   want reply
     *
     * This message will request that the user's default shell (typically
     * defined in /etc/passwd in UNIX systems) be started at the other end.
     */
    boolean wantReply = req.readBoolean();

    logger.debug("[{}] Received shell request. want reply:{}", this, wantReply);

    return true;
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + " [id=" + id + " peerId=" + peerId + "]";
  }
}
