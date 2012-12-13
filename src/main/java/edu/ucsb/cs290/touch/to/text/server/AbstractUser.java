package edu.ucsb.cs290.touch.to.text.server;


import edu.ucsb.cs290.touch.to.text.remote.messages.ProtectedMessage;
import edu.ucsb.cs290.touch.to.text.remote.messages.TokenAuthMessage;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author charlesmunger
 */
public abstract class AbstractUser<IDTYPE> implements Serializable {
    private final Set<UUID> blacklist = Collections.synchronizedSet( new TreeSet<UUID>());
    private final PublicKey key;
    
    protected AbstractUser(PublicKey key) {
        this.key = key;
    }
    
    public void sendMessage(TokenAuthMessage m) {
        try {
            if (blacklist.contains((UUID)m.getToken().getObject())) {
                return;
            }
        } catch (Exception e) {
            Logger.getLogger("touch-to-text-server").log(Level.SEVERE,
                    "Error checking if token in blacklist.", e);
            return;
        }
        ProtectedMessage pm = m.getMessage();
        sendMessage(pm);
    }
    
    void ban(UUID banned) {
        blacklist.add(banned);
    }
    
    protected abstract void sendMessage(ProtectedMessage m);
    protected abstract void updateID(IDTYPE i);
}
