package org.crypto.pir;

import junit.framework.TestCase;
import org.crypto.jpir.crypto.HE;
import org.crypto.jpir.crypto.Paillier;
import org.crypto.jpir.crypto.PaillierPrivateKey;
import org.crypto.jpir.crypto.PaillierPublicKey;
import org.crypto.pir.client.COSIMP_ClientImpl;
import org.crypto.pir.server.COSIMP_ServerImpl;
import org.crypto.pir.psdr.SpamFile;
import org.crypto.pir.psdr.UserFile;
import org.crypto.jpir.util.Settings;
import org.crypto.pir.util.PPTISettings;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

/**
 *    PPTI ( Privacy Preserving Threat Intelligence) is research project.
 *
 *    Private Similar Document Retrieval (PSDR)
 *
 *    Cosine Similar based PIR Algorithm written by Sashank Dara (sashank.dara@gmail.com)
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 2 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public
 *    License along with this library; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **/
public class TestCOSIMP extends TestCase {
    private COSIMP_ClientImpl client;
    private COSIMP_ServerImpl server;
    private HE he;
    private Properties clientProperties,serverProperties;
    private String testFile;
    private Double similarity = 0.8;
    private int keySize = 1024;
    public void setUp() throws Exception {
        super.setUp();
        init();
        int keySize =  Integer.valueOf(clientProperties.getProperty(Settings.KEYSIZE));
        String cipher = clientProperties.getProperty(Settings.CIPHER);
        similarity = Double.valueOf(clientProperties.getProperty(PPTISettings.SIMILARITY));

        String publicKeyStr = clientProperties.getProperty(Settings.PUBLIC_KEY);
        String privateKeyStr = clientProperties.getProperty(Settings.PRIVATE_KEY);
        String clientInputDir = clientProperties.getProperty(Settings.INPUTDIR);
        int clientLimit = Integer.valueOf(clientProperties.getProperty(PPTISettings.FILE_MIN_LIMIT));
        testFile = "mbox29";
        SecureRandom rnd = new SecureRandom();
        he = new Paillier(keySize, rnd,publicKeyStr,privateKeyStr);
        client = new COSIMP_ClientImpl(clientInputDir, he, similarity, true,clientLimit);


        String serverInputDir = serverProperties.getProperty(Settings.INPUTDIR);
        String pubKey = serverProperties.getProperty(Settings.PUBLIC_KEY);
        Double sim = Double.valueOf(serverProperties.getProperty(PPTISettings.SIMILARITY));
        String limit = serverProperties.getProperty(PPTISettings.FILE_MIN_LIMIT);
        SecureRandom rnd2 = new SecureRandom();
        HE he2 = new Paillier(keySize, rnd2,pubKey,"");

        server = new COSIMP_ServerImpl(serverInputDir, he2, sim, Integer.valueOf(limit));

        HashMap<String, Double> serverMagMap = new HashMap<>();
        for(SpamFile spamFile : server.getSpamFiles()) {
            serverMagMap.put(spamFile.getFileName(),spamFile.getMagnitude());
        }
        client.setServerMagPerFile(serverMagMap);
    }

    public void testCosineSimilarity() throws Exception {

        COSIMP_ServerImpl serverCosimp = new COSIMP_ServerImpl("in/", he, similarity, 10);
        COSIMP_ClientImpl clientCosimp = new COSIMP_ClientImpl("in/", he, similarity, false,10);

        for(SpamFile spamFile : serverCosimp.getSpamFiles()) {
            String serverFileName = spamFile.getFileName();
            for (UserFile clientFile : clientCosimp.getUserFiles()) {
                String clientFileName = clientFile.getFileName();
                double cosim =  serverCosimp.cosineSimilarity(clientFile, spamFile);
                if(Math.floor(cosim) > similarity) {
                    System.out.println(serverFileName + " " + clientFileName + " are similar " + cosim);
                    assertTrue("Cosine Similarity works ", true);
                }
            }
        }
    }

    public void testPrivateQuery() throws Exception{
        UserFile userFile = client.getUserFile(testFile);
        ArrayList<BigInteger> privateQuery = userFile.getPrivateTfIdfVector();
        ArrayList<Integer> query = userFile.getTfIdfVector();

        for (int i = 0 ; i < query.size(); i++) {
            BigInteger dec = he.decrypt(privateQuery.get(i));
            if (query.get(i) == dec.intValue())
                assertTrue("Private Query works ", true);
            else
                assertTrue("Private Query Does not works ", false);
        }

    }

    public  ArrayList<BigInteger> getBigInteger(ArrayList<Integer> tfIdfVector) {
        ArrayList<BigInteger> bigIntegers = new ArrayList<>(tfIdfVector.size());
        for(Integer tfidf: tfIdfVector)
            bigIntegers.add(new BigInteger(String.valueOf(tfidf)));
        return bigIntegers;
    }
    public void testPrivateSQ() throws Exception{
        UserFile userFile = client.getUserFile(testFile);
        ArrayList<BigInteger> privateQuery = userFile.getPrivateTfIdfVector();
        ArrayList<Integer> query = userFile.getTfIdfVector();

        ArrayList<Integer> plainTFIDF = server.getSpamFile(testFile).getTfIdfVector();

        if(plainTFIDF != null) {
            BigInteger privateSQ = server.privateSq(privateQuery, getBigInteger(plainTFIDF));
            Integer sq = server.sq(query, plainTFIDF);

            BigInteger bigSQ = he.decrypt(privateSQ);
            Integer resSQ = bigSQ.intValue();

            if (sq.equals(resSQ))
                assertTrue("Private Similarity Quotient works", true);
            else
                assertTrue("Private Similarity Quotient Does not works", false);
        }

    }
    public void testPrivateCoSim() throws Exception {
        UserFile userFile = client.getUserFile(testFile);
        ArrayList<BigInteger> privateQuery = userFile.getPrivateTfIdfVector();

        HashMap<String, BigInteger> privateRes = server.processPrivateQuery(privateQuery);
        HashMap<String, Double> responseMap = client.extractPrivateResponse(testFile, privateRes);
        HashMap<String, Double> realMap = server.processQuery(userFile);

        for (String realFile : realMap.keySet()) {
            for (String resFile : responseMap.keySet()) {
                if(resFile.equals(realFile)) {
                    if (responseMap.get(resFile).equals(realMap.get(realFile)))
                        assertTrue("Similarity between " + resFile + " " + realFile, true);
                    else
                        assertTrue("Similarity between " + resFile + " " + realFile, false);
                }
            }
        }

    }

    private void init() {
        SecureRandom rnd = new SecureRandom();
        he = new Paillier(keySize, rnd);
        PaillierPublicKey publicKey = (PaillierPublicKey) he.getKeyPair().getPublic();
        PaillierPrivateKey privateKey = (PaillierPrivateKey) he.getKeyPair().getPrivate();

        clientProperties = new Properties();
        serverProperties = new Properties();

        //load the file else create new
        try (InputStream in = new FileInputStream("client.properties")) {
            clientProperties.load(in);
        } catch (IOException e) {
            //e.printStackTrace();
            try (OutputStream out = new FileOutputStream("client.properties")) {
                clientProperties.setProperty(Settings.CIPHER, Settings.PAILLIER);
                clientProperties.setProperty(Settings.KEYSIZE, String.valueOf(keySize));
                clientProperties.setProperty(PPTISettings.SIMILARITY, String.valueOf(similarity));
                clientProperties.setProperty(Settings.PUBLIC_KEY, publicKey.getN().toString());
                clientProperties.setProperty(Settings.PRIVATE_KEY, privateKey.getL().toString());
                clientProperties.setProperty(Settings.INPUTDIR, "in/");
                clientProperties.setProperty(Settings.SERVER_IP, "0.0.0.0"); // Gcloud Server
                clientProperties.setProperty(Settings.SERVER_PORT, "4567");
                clientProperties.setProperty(PPTISettings.PERF_METER, "on");
                clientProperties.setProperty(PPTISettings.FILE_MIN_LIMIT, "3");;
                clientProperties.setProperty(PPTISettings.FILE_MAX_LIMIT, "30");;
                clientProperties.setProperty(PPTISettings.FILE_INTERVAL, "3");;
                clientProperties.store(out,"PPTI Client Preferences");

            } catch (IOException writeException) {
                writeException.printStackTrace();
            }
        }

        try (InputStream in = new FileInputStream("server.properties")) {
            serverProperties.load(in);
        } catch (IOException e) {
           // e.printStackTrace();
            try (OutputStream out = new FileOutputStream("server.properties")) {
                serverProperties = new Properties();
                serverProperties.setProperty(Settings.CIPHER, Settings.PAILLIER);
                serverProperties.setProperty(Settings.KEYSIZE, String.valueOf(keySize));
                serverProperties.setProperty(PPTISettings.SIMILARITY, String.valueOf(similarity));
                serverProperties.setProperty(Settings.PUBLIC_KEY, publicKey.getN().toString());
                serverProperties.setProperty(Settings.INPUTDIR, "in/");
                serverProperties.setProperty(PPTISettings.FILE_MIN_LIMIT, "100"); // Not used
                serverProperties.setProperty(PPTISettings.FILE_MAX_LIMIT, "1000");
                serverProperties.setProperty(PPTISettings.FILE_INTERVAL, "100"); // Not used
                serverProperties.setProperty(Settings.SERVER_PORT, "4567");
                serverProperties.store(out,"PPTI Server Preferences");

            } catch (IOException writeException) {
                writeException.printStackTrace();
            }
        }
    }
}