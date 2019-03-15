package io.github.grantchan.ssh.client.userauth.method;

import io.github.grantchan.ssh.common.Session;

public interface Method {

  boolean submit(Session session);

  boolean authenticate(Session session);
}
