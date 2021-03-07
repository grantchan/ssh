package io.github.grantchan.sshengine.server.connection;

import io.github.grantchan.sshengine.common.connection.TtyMode;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class TtyInputStreamTest {
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

  private static final String data = String.join("\r\n", LINES);

  @Parameter(0)
  public TtyMode mode;
  @Parameter(1)
  public int expectedNumberOfCR;
  @Parameter(2)
  public int expectedNumberOfLF;

  @Parameters(name = "{index}: mode={0}")
  public static Collection<Object[]> parameters() {
    int numberOfLines = LINES.size() - 1;
    int dblNumberOfLines = (LINES.size() - 1) << 1;

    return Arrays.asList(new Object[][] {
        { TtyMode.ECHO,   numberOfLines   , numberOfLines    },
        { TtyMode.ONLCR,  numberOfLines   , numberOfLines    },
        { TtyMode.OCRNL,  0               , dblNumberOfLines },
        { TtyMode.ONLRET, dblNumberOfLines, 0                },
        { TtyMode.ONOCR,  numberOfLines   , numberOfLines    }
    });
  }

  @Test
  public void whenUsingDifferentTtyMode_shouldProduceDifferentCRAndLF() throws IOException {
    try (ByteArrayInputStream bais = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
         TtyInputStream tty = new TtyInputStream(bais, EnumSet.of(mode))) {
      final AtomicInteger actualNumberOfCR = new AtomicInteger(0);
      final AtomicInteger actualNumberOfLF = new AtomicInteger(0);

      int c;
      do {
        c = tty.read();
        if (c == '\r') {
          actualNumberOfCR.incrementAndGet();
        } else if (c == '\n') {
          actualNumberOfLF.incrementAndGet();
        }
      } while (c != -1);

      assertEquals("", expectedNumberOfCR, actualNumberOfCR.get());
      assertEquals("", expectedNumberOfLF, actualNumberOfLF.get());
    }
  }
}