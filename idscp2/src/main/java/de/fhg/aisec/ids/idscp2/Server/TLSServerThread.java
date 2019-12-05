package de.fhg.aisec.ids.idscp2.Server;

import de.fhg.aisec.ids.idscp2.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/**
 * A TLS server thread implementation for the IDSCPv2 protocol.
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */

public class TLSServerThread extends Thread implements ServerThread, HandshakeCompletedListener {
    private static final Logger LOG = LoggerFactory.getLogger(TLSServerThread.class);

    private SSLSocket sslSocket;
    private volatile boolean running = true;
    private InputStream in;
    private OutputStream out;
    private boolean tlsHandshakeCompleted = false;
    private boolean sendServerGoodbye = true;
    private ServerNodeSynchronizer serverNodeSynchronizer = null;
    private String connectionId; //unique server - client connection id, that identifies this serverThread

    TLSServerThread(SSLSocket sslSocket, String connectionId){
        this.sslSocket = sslSocket;
        this.connectionId = connectionId;

        try {
            //set timout for blocking read
            sslSocket.setSoTimeout(5000);
            in = sslSocket.getInputStream();
            out = sslSocket.getOutputStream();
        } catch (IOException e){
            LOG.error(e.getMessage());
            running = false;
        }
    }

    @Override
    public void run(){
        //wait for new data while running
        byte[] buf = new byte[2048];

        while (running){
            try {
                int len = in.read(buf, 0, buf.length - 1);
                if (0 > len) {
                    onMessage(Constants.END_OF_STREAM.length(), Constants.END_OF_STREAM.getBytes());
                    running = false;
                } else {
                    onMessage(len, buf);
                }
            } catch (SocketTimeoutException e){
                //timeout catches safeStop() call and allows to send server_goodbye
                //alternative: close sslSocket and catch SocketException
                //continue
            } catch (SSLException e){
                LOG.error("SSL error");
                e.printStackTrace();
                running = false;
                return;
            } catch (IOException e){
                e.printStackTrace();
                running = false;
            }
        }
        try {
            if (sendServerGoodbye)
                send(Constants.SERVER_GOODBYE);
            out.close();
            in.close();
            sslSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //unregister from main server
        if (this.serverNodeSynchronizer != null)
            this.serverNodeSynchronizer.unregisterServerOnClose(this.connectionId);
    }

    @Override
    public void send(byte[] data) {
        if (!isConnected()){
            LOG.error("Server cannot send data because socket is not connected");
        } else {
            try {
                out.write(data);
                out.flush();
                LOG.info("Send message: " + new String(data));
            } catch (IOException e){
                LOG.error("Server cannot send data");
                e.printStackTrace();
            }
        }
    }

    public void send(String data){
        send(data.getBytes());
    }

    public void onMessage(int len, byte[] rawData) {
        String data = new String(rawData, 0, len, StandardCharsets.UTF_8);
        if (data.equals(Constants.END_OF_STREAM) ||
                data.equals(Constants.CLIENT_GOODBYE)){
            //End of stream or client goodbye, connection is no longer available
            running = false; //terminate server
            LOG.info("Server is terminating after client disconnect");
            sendServerGoodbye = false;
        } else {
            //toDo do something with the received data
            System.out.println("New data received: " + data);
        }
    }

    public void safeStop(){
        running = false;
    }

    @Override
    public boolean isConnected() {
        return (sslSocket != null && sslSocket.isConnected());
    }

    @Override
    public void registerListener(ServerNodeSynchronizer serverNodeSynchronizer) {
        this.serverNodeSynchronizer = serverNodeSynchronizer;
    }

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent) {
        tlsHandshakeCompleted = true;
        LOG.info("TLS handshake was successful");
    }
}
