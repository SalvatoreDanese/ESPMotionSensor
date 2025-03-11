import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


// Server class
class Server {

    public volatile static boolean movement = false;

    public static void main(String[] args)
    {
        ServerSocket server = null;
        byte bobPrivate[] = {(byte)0x5d, (byte) 0xab,(byte) 0x08, (byte)0x7e, (byte)0x62, (byte)0x4a, (byte) 0x8a,(byte) 0x4b,
                (byte)0x79, (byte) 0xe1, (byte)0x7f, (byte) 0x8b, (byte) 0x83, (byte) 0x80, (byte)0x0e, (byte) 0xe6,
                (byte)0x6f, (byte)0x3b, (byte) 0xb1,(byte) 0x29, (byte)0x26, (byte)0x18, (byte) 0xb6, (byte) 0xfd,
                (byte)0x1c, (byte)0x2f, (byte) 0x8b, (byte)0x27, (byte) 0xff, (byte) 0x88, (byte) 0xe0, (byte) 0xeb};

        byte alicePublic[] = {(byte) 0x85, (byte)0x20, (byte) 0xf0, (byte)0x09, (byte) 0x89, (byte)0x30, (byte) 0xa7,(byte) 0x54,
                (byte)0x74, (byte) 0x8b, (byte)0x7d, (byte) 0xdc, (byte) 0xb4, (byte)0x3e, (byte) 0xf7,(byte) 0x5a,
                (byte)0x0d, (byte) 0xbf, (byte)0x3a, (byte)0x0d, (byte)0x26, (byte)0x38, (byte)0x1a, (byte) 0xf4,
                (byte) 0xeb, (byte) 0xa4, (byte) 0xa9, (byte) 0x8e, (byte) 0xaa, (byte) 0x9b, (byte)0x4e, (byte)0x6a};


        bobPrivate[0] &= (byte)0xF8;
        bobPrivate[31] = (byte) ((bobPrivate[31] & 0x7F) | 0x40);
        try {

            // server is listening on port 1234
            InetAddress addr = InetAddress.getByName("172.20.10.4");
            server = new ServerSocket(1234,0, addr);
            server.setReuseAddress(true);
            System.out.println(server.getInetAddress());

            // running infinite loop for getting
            // client request
            while (true) {

                // socket object to receive incoming client
                // requests
                Socket client = server.accept();

                // Displaying that new client is connected
                // to server
                System.out.println("New client connected: "
                        + client.getInetAddress()
                        .getHostAddress());


                // create a new thread object
                ClientHandler clientSock
                        = new ClientHandler(client);

                // This thread will handle the client
                // separately
                new Thread(clientSock).start();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (server != null) {
                try {
                    server.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // ClientHandler class
    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        byte sharedSecret1[] = { (byte)0x4a, (byte)0x5d, (byte)0x9d, (byte)0x5b, (byte)0xa4, (byte)0xce, (byte)0x2d, (byte)0xe1,
                (byte)0x72, (byte)0x8e, (byte)0x3b, (byte)0xf4, (byte)0x80, (byte)0x35, (byte)0x0f, (byte)0x25};

        byte sharedSecret2[] = { (byte)0x97, (byte)0x94, (byte)0x13, (byte)0x9c, (byte)0xd4, (byte)0xff, (byte)0x86, (byte)0x1f,
                (byte)0x0e, (byte)0x17, (byte)0xba, (byte)0x0e, (byte)0x73, (byte)0x1b, (byte)0x7d, (byte)0x45};
        byte iv[] = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};

        byte iv1[] = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};

        byte iv2[] = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};

        // Constructor
        public ClientHandler(Socket socket)
        {
            this.clientSocket = socket;
        }

        public void run()
        {
            OutputStream out = null;
            BufferedReader in = null;
            try {

                // get the outputstream of client
                out = clientSocket.getOutputStream();

                // get the inputstream of client
                in = new BufferedReader(
                        new InputStreamReader(
                                clientSocket.getInputStream()));

                if(in.readLine().equals("1")) {

                    System.out.println("Client 1 connected");

                    String line;

                    Random ran = new Random();
                    byte b[] = new byte[2];
                    ran.nextBytes(b);

                    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    Key x = new SecretKeySpec(sharedSecret1, "AES");
                    cipher.init(Cipher.ENCRYPT_MODE, x, new IvParameterSpec(iv));

                    byte outB[] = cipher.doFinal(b);

                    out.write(outB);

                    System.out.println(outB[0] & 0xFF);
                    System.out.println(outB[1] & 0xFF);
                    System.out.println(b[0] & 0xFF);
                    System.out.println(b[1] & 0xFF);

                    for(int i = 0; i < 16; i++){
                        iv1[i] = iv[i];
                        iv1[i] ^= b[0]&0xFF;
                    }


                    while ((line = in.readLine()) != null) {

                        // writing the received message from
                        // client
                        cipher = Cipher.getInstance("AES/CTR/NoPadding");
                        x = new SecretKeySpec(sharedSecret1, "AES");
                        cipher.init(Cipher.DECRYPT_MODE, x, new IvParameterSpec(iv1));
                        String[] modeledLine = line.split("x", 2);
                        byte[] bytes = new byte[2];
                        bytes[0] = (byte) (Integer.parseInt(modeledLine[0]) & 0xFF);
                        bytes[1] = (byte) (Integer.parseInt(modeledLine[1]) & 0xFF);
                        byte[] plainText = cipher.doFinal(bytes);


                        if(plainText[0] == 65 && plainText[1] == 65) {
                            movement = true;
                            System.out.println("Motion detected");
                        }

                        else if(plainText[0] == 66 && plainText[1] == 66){

                        }
                    }
                }


                else{
                    System.out.println("Client 2 connected");

                    Random ran = new Random();
                    byte b[] = new byte[2];
                    ran.nextBytes(b);

                    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    Key x = new SecretKeySpec(sharedSecret2, "AES");
                    cipher.init(Cipher.ENCRYPT_MODE, x, new IvParameterSpec(iv));

                    byte outB[] = cipher.doFinal(b);

                    out.write(outB);

                    System.out.println(outB[0] & 0xFF);
                    System.out.println(outB[1] & 0xFF);
                    System.out.println(b[0] & 0xFF);
                    System.out.println(b[1] & 0xFF);

                    for(int i = 0; i < 16; i++){
                        iv2[i] = iv[i];
                        iv2[i] ^= b[0]&0xFF;
                    }

                    cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    x = new SecretKeySpec(sharedSecret2, "AES");
                    cipher.init(Cipher.ENCRYPT_MODE, x, new IvParameterSpec(iv2));
                    byte[] entered = {0x68};

                    while(true){

                            if(movement){
                                System.out.println("mov true");
                                byte[] ciphertext = cipher.doFinal(entered);
                                try {
                                    out.write(ciphertext);
                                }
                                catch (SocketException s) {

                                }
                                finally {
                                    movement = false;
                                }


                            }

                    }



                }
            }
            catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    if (out != null) {
                        out.close();
                    }
                    if (in != null) {
                        in.close();
                        clientSocket.close();
                    }
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
