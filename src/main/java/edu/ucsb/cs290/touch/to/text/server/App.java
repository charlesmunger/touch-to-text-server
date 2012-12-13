package edu.ucsb.cs290.touch.to.text.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SignedObject;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import edu.ucsb.cs290.touch.to.text.remote.messages.TokenAuthMessage;
import edu.ucsb.cs290.touch.to.text.remote.register.RegisterUser;

/**
 * Hello world!
 *
 */
public class App {

	private static final ConcurrentMap<PublicKey, AbstractUser> keyToGCMID = new ConcurrentHashMap<PublicKey, AbstractUser>();
	private static final Object notifier  = new Object();
	static {
		java.security.Security.addProvider(new BouncyCastleProvider());
	}
	@SuppressWarnings("restriction")
	public static void main(String[] args) {
		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					File f = new File("data.dat");
					if(f.exists()) {
						ObjectInputStream oi = new ObjectInputStream(new FileInputStream(f));
						ConcurrentMap<PublicKey, AbstractUser> m = (ConcurrentMap<PublicKey, AbstractUser>) oi.readObject();
						oi.close();
						keyToGCMID.putAll(m);
					}
					synchronized(notifier) {
						while(true) {
							notifier.wait();
							final ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream(new File("data.dat")));
							o.writeObject(keyToGCMID);
							o.close();
						}
					}
				} catch(Exception e ) {
					e.printStackTrace();
				}
			}
		}).start();
		HttpsServer server = null;
		Logger.getLogger(App.class.getName()).setLevel(Level.ALL);
		try {
			InetSocketAddress address = new InetSocketAddress(12345);
			server = HttpsServer.create(address, 0);
			SSLContext sslContext = SSLContext.getInstance("TLS");
			char[] password = "changeit".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(
					"../assets/server_keystore.jks");
			ks.load(fis, password);
			fis.close();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, password);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ks);
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
				@Override
				public void configure(HttpsParameters params) {
					try {
						//  get SSL context for this configurator
						SSLContext c = getSSLContext();

						//  get the default settings for this SSL context
						SSLParameters sslparams = c.getDefaultSSLParameters();

						//  set parameters for the HTTPS connection.
						params.setNeedClientAuth(false);
						params.setSSLParameters(sslparams);
						System.out.println("SSL context created ...\n");

					} catch (Exception e2) {
						System.out.println("Invalid parameter ...\n");
						e2.printStackTrace();
					}
				}
			});

		} catch (Exception ex) {
			Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
		}
		//Returns requests with no information, preventing directory crawling. 
		server.createContext("/", new HttpHandler() {
			@Override
			public void handle(HttpExchange he) throws IOException {
				debug(he);
				System.out.println("Stuff found");
				he.close();
			}
		});

		server.createContext("/" + TokenAuthMessage.FIELD_NAME, new HttpHandler() {
			@Override
			public void handle(HttpExchange he) throws IOException {
				debug(he);
				try {
					System.out.println("Stuff recieved on send");
					TokenAuthMessage tm = (TokenAuthMessage) getObject(he,TokenAuthMessage.FIELD_NAME);
					SignedObject token = tm.getToken();
					UUID uuid = (UUID)token.getObject();
					System.out.println("Token auth message successfully deserialized: " + uuid.toString());
					AbstractUser get = keyToGCMID.get(tm.getDestination());
					if (get != null) {
						get.sendMessage(tm);
						he.sendResponseHeaders(200, 0l);
					} else {
						he.sendResponseHeaders(404, 0l);
					}

				} catch (Exception e) {
					e.printStackTrace();
				} finally {
					he.close();
				}
			}
		});
		server.createContext("/" + RegisterUser.FIELD_NAME, new HttpHandler() {
			@Override
			public void handle(HttpExchange he) throws IOException {
				debug(he);
				System.out.println("Stuff received on register!");
				try {
					RegisterUser r = (RegisterUser) getObject(he, RegisterUser.FIELD_NAME);
					String regID = r.getRegId();
					final GCMUser user = new GCMUser(r.getKey(), regID);
					AbstractUser currentUser = keyToGCMID.putIfAbsent(r.getKey(), user);
					if(currentUser!=null) {
						currentUser.updateID(regID);
					} else {
						user.updateID(regID);
					}

					System.out.println("REgister user worked!");
					he.sendResponseHeaders(200, 0);
				} catch (Exception ex) {
					ex.printStackTrace();
				} finally {
					he.close();
					synchronized(notifier) {
						notifier.notify();
					}
				}
			}
		});
		server.setExecutor(Executors.newCachedThreadPool());
		server.start();

		}

		private static Object getObject(HttpExchange he, String field) throws IOException, ClassNotFoundException {
			return (new ObjectInputStream(he.getRequestBody())).readObject();
		}

		private static void debug(HttpExchange exchange) {
			Headers requestHeaders = exchange.getRequestHeaders();
			Set<String> keySet = requestHeaders.keySet();
			Iterator<String> iter = keySet.iterator();
			while (iter.hasNext())
			{
				String key = iter.next();
				List values = requestHeaders.get(key);
				String response = key + " = " + values.toString() + "\n";
				System.out.print(response);
			}
		}
	}
