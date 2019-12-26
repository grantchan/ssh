package io.github.grantchan.sshengine.common.connection;

/**
 * <p>
 * Encoded terminal modes
 * </p>
 *
 * <p>
 * All 'encoded terminal modes' (as passed in a pty request) are encoded
 * into a byte stream.  It is intended that the coding be portable
 * across different environments.  The stream consists of opcode-
 * argument pairs wherein the opcode is a byte value.  Opcodes 1 to 159
 * have a single uint32 argument.  Opcodes 160 to 255 are not yet
 * defined, and cause parsing to stop (they should only be used after
 * any other data).  The stream is terminated by opcode TTY_OP_END
 * (0x00).
 * </p>
 *
 * <p>
 * The client SHOULD put any modes it knows about in the stream, and the
 * server MAY ignore any modes it does not know about.  This allows some
 * degree of machine-independence, at least between systems that use a
 * POSIX-like tty interface.  The protocol can support other systems as
 * well, but the client may need to fill reasonable values for a number
 * of parameters so the server pty gets set to a reasonable mode (the
 * server leaves all unspecified mode bits in their default values, and
 * only some combinations make sense).
 * </p>
 *
 * @see <a href=https://tools.ietf.org/html/rfc4254#section-8>8. Encoding of Terminal Modes</a>
 */
public enum TtyMode {

/*
  The naming of opcode values mostly follows the POSIX terminal mode
  flags.  The following opcode values have been defined.  Note that the
  values given below are in decimal format for readability, but they
  are actually byte values.
*/

/* mnemonic    (opcode)  description */

  TTY_OP_END   (0),      // Indicates end of options.

  VINTR        (1),      // Interrupt character; 255 if none. Similarly for the other characters.
                         // Not all of these characters are supported on all systems.
  VQUIT        (2),      // The quit character (sends SIGQUIT signal on POSIX systems).
  VERASE       (3),      // Erase the character to left of the cursor.
  VKILL        (4),      // Kill the current input line.
  VEOF         (5),      // End-of-file character (sends EOF from the terminal).
  VEOL         (6),      // End-of-line character in addition to carriage return and/or linefeed.
  VEOL2        (7),      // Additional end-of-line character.
  VSTART       (8),      // Continues paused output (normally control-Q).
  VSTOP        (9),      // Pauses output (normally control-S).
  VSUSP        (10),     // Suspends the current program.
  VDSUSP       (11),     // Another suspend character.
  VREPRINT     (12),     // Reprints the current input line.
  VWERASE      (13),     // Erases a word left of cursor.
  VLNEXT       (14),     // Enter the next character typed literally, even if it is a special
                         // character
  VFLUSH       (15),     // Character to flush output.
  VSWTCH       (16),     // Switch to a different shell layer.
  VSTATUS      (17),     // Prints system status line (load, command, pid, etc).
  VDISCARD     (18),     // Toggles the flushing of terminal output.

  IGNPAR       (30),     // The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE,
                         // and 1 if it is TRUE.
  PARMRK       (31),     // Mark parity and framing errors.
  INPCK        (32),     // Enable checking of parity errors.
  ISTRIP       (33),     // Strip 8th bit off characters.
  INLCR        (34),     // Map NL into CR on input.
  IGNCR        (35),     // Ignore CR on input.
  ICRNL        (36),     // Map CR to NL on input.
  IUCLC        (37),     // Translate uppercase characters to lowercase.
  IXON         (38),     // Enable output flow control.
  IXANY        (39),     // Any char will restart after stop.
  IXOFF        (40),     // Enable input flow control.
  IMAXBEL      (41),     // Ring bell on input queue full.

  ISIG         (50),     // Enable signals INTR, QUIT, [D]SUSP.
  ICANON       (51),     // Canonicalize input lines.
  XCASE        (52),     // Enable input and output of uppercase characters by preceding their
                         // lowercase equivalents with "\".
  ECHO         (53),     // Enable echoing.
  ECHOE        (54),     // Visually erase chars.
  ECHOK        (55),     // Kill character discards current line.
  ECHONL       (56),     // Echo NL even if ECHO is off.
  NOFLSH       (57),     // Don't flush after interrupt.
  TOSTOP       (58),     // Stop background jobs from output.
  IEXTEN       (59),     // Enable extensions.
  ECHOCTL      (60),     // Echo control characters as ^(Char).
  ECHOKE       (61),     // Visual erase for line kill.
  PENDIN       (62),     // Retype pending input.
  OPOST        (70),     // Enable output processing.
  OLCUC        (71),     // Convert lowercase to uppercase.
  ONLCR        (72),     // Map NL to CR-NL.
  OCRNL        (73),     // Translate carriage return to newline(output).
  ONOCR        (74),     // Translate newline to carriage return-newline (output).
  ONLRET       (75),     // Newline performs a carriage return(output).

  CS7          (90),     // 7 bit mode.
  CS8          (91),     // 8 bit mode.
  PARENB       (92),     // Parity enable.
  PARODD       (93),     // Odd parity, else even.

  TTY_OP_ISPEED(128), // Specifies the input baud rate in bits per second.
  TTY_OP_OSPEED(129);  // Specifies the output baud rate in bits per second.

  private final int opcode;

  TtyMode(int opcode) {
    this.opcode = opcode;
  }
}
