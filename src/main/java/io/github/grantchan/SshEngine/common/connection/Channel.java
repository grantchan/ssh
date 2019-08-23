package io.github.grantchan.SshEngine.common.connection;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public interface Channel {

  AtomicInteger idGenerator = new AtomicInteger(0);

  Map<Integer, Channel> channels = new ConcurrentHashMap<>();

  default int register(Channel channel) {
    int id = idGenerator.getAndIncrement();

    channels.put(id, channel);

    return id;
  }

  int getId();
}
