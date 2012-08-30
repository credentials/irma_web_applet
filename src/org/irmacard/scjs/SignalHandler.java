package org.irmacard.scjs;

import java.util.EventListener;

public interface SignalHandler extends EventListener {

    public void handle(Signal signal);
}
