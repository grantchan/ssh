package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.connection.TtyMode;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class TtyOutputStreamTest {

  private static final List<String> LINES =
      Arrays.asList(
          "A quick brown fox jumps over the lazy dog.",
          "The five boxing wizards jump quickly.",
          "A quick movement of the enemy will jeopardize six gunboats.",
          "Who packed five dozen old quart jugs in my box?",
          "The quick brown fox jumped over the lazy dogs.",
          "Few black taxis drive up major roads on quiet hazy nights.",
          "Pack my box with five dozen liquor jugs.",
          "My girl wove six dozen plaid jackets before she quit.",
          "Pack my red box with five dozen quality jugs."
      );

  @Parameter(0)
  public TtyMode mode;
  @Parameter(1)
  public int expectedNumberOfCR;
  @Parameter(2)
  public int expectedNumberOfLF;

  @Parameters(name = "{index}: mode={0}")
  public static Collection<Object[]> parameters() {
    int numberOfLines = LINES.size();
    int dblNumberOfLines = LINES.size() << 1;

    return Arrays.asList(new Object[][] {
        { TtyMode.ECHO , numberOfLines   , numberOfLines    },
        { TtyMode.INLCR, dblNumberOfLines, 0                },
        { TtyMode.ICRNL, 0               , dblNumberOfLines },
        { TtyMode.IGNCR, 0               , numberOfLines    }
    });
  }

  @Test
  public void whenUsingDifferentTtyMode_shouldProduceDifferentCRAndLF() throws IOException {
    final AtomicInteger actualNumberOfCR = new AtomicInteger(0);
    final AtomicInteger actualNumberOfLF = new AtomicInteger(0);

    Set<TtyMode> modes = TtyMode.ECHO.equals(mode) ? Collections.emptySet() : EnumSet.of(mode);
    try (OutputStream out = new OutputStream() {
      @Override
      public void write(int i) {
        if (i == '\r') {
          actualNumberOfCR.incrementAndGet();
        } else if (i == '\n') {
          actualNumberOfLF.incrementAndGet();
        }
      }
    };

         TtyOutputStream tty = new TtyOutputStream(out, null, modes);
         Writer writer = new OutputStreamWriter(tty, StandardCharsets.UTF_8)) {

      for (String line : LINES) {
        writer.append(line).append("\r\n");
      }
    }

    assertEquals("Number of CR is mismatched", expectedNumberOfCR, actualNumberOfCR.get());
    assertEquals("Number of LF is mismatched", expectedNumberOfLF, actualNumberOfLF.get());
  }
}