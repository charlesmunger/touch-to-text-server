package edu.ucsb.cs290.touch.to.text.server;

import com.google.android.gcm.server.Message;
import com.google.android.gcm.server.Result;
import com.google.android.gcm.server.Sender;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import edu.ucsb.cs290.touch.to.text.remote.Helpers;
import edu.ucsb.cs290.touch.to.text.remote.messages.ProtectedMessage;
import edu.ucsb.cs290.touch.to.text.server.AbstractUser;
import java.io.IOException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Used for server-side storage of user information, including keys, GCM ID, 
 * and code for sending the actual message. 
 * @author charlesmunger
 */
class GCMUser extends AbstractUser<String> {
    private String GCMID;
    
    public GCMUser(PublicKey key, String GCMID) {
        super(key);
        this.GCMID = GCMID;
    }

    @Override
    protected synchronized void updateID(String GCMID) {
        this.GCMID = GCMID;
    }

    @Override
    protected synchronized void sendMessage(ProtectedMessage m) {
        Message me = new Message.Builder().addData("message", Base64.encode(Helpers.serialize(m))).build();
        Sender s = new Sender("AIzaSyDY2yocB-HfzJ7x4bknPtJiS4oqeSmB1jg");
        try {
            Result send = s.send(me, GCMID, 3);
            System.out.println(send.toString());
        } catch (IOException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
