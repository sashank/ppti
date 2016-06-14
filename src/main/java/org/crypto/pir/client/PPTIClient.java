package org.crypto.pir.client;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.crypto.jpir.crypto.HE;
import org.crypto.jpir.crypto.Paillier;
import org.crypto.jpir.util.Settings;
import org.crypto.pir.server.COSIMP_ServerImpl;
import org.crypto.pir.psdr.SpamFile;
import org.crypto.pir.psdr.UserFile;
import org.crypto.pir.util.PPTISettings;
import org.crypto.pir.util.PerfMeter;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/*
*    PPTI ( Privacy Preserving Threat Intelligence) is research project.
*
*    PPTIClient is written by Sashank Dara(sashank.dara@gmail.com).
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
class PPTIClient {

    private  String pptiServer;
    private COSIMP_ClientImpl cosimpClient;
    private  Properties preferences;
    private  HE he ;
    private  Double similarity;
    private  String inputDir;
    private  String perfMeterStr;
    private  static String preferencesFile;
    private  int    responseSize;
    private  int fileLimit;
    private  int fileMinLimit;
    private  int fileMaxLimit;
    private  int fileInterval;
    PPTIClient() {
        try {
            init();
        }  catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to Init PPTI Client");
            System.exit(0);
        }

    }

    private void init() throws Exception {
        getPreferences();
        SecureRandom rnd = new SecureRandom();
        int keySize =  Integer.valueOf(preferences.getProperty(Settings.KEYSIZE));
        String cipher = preferences.getProperty(Settings.CIPHER);
        similarity = Double.valueOf(preferences.getProperty(PPTISettings.SIMILARITY));
        String serverIp = preferences.getProperty(Settings.SERVER_IP);
        String serverPort = preferences.getProperty(Settings.SERVER_PORT);
        pptiServer =   "http://"+ serverIp+ ":"+serverPort +"/" ;
        inputDir = preferences.getProperty(Settings.INPUTDIR);
        perfMeterStr = preferences.getProperty(PPTISettings.PERF_METER);
        fileMinLimit = Integer.valueOf(preferences.getProperty(PPTISettings.FILE_MIN_LIMIT));
        fileMaxLimit = Integer.valueOf(preferences.getProperty(PPTISettings.FILE_MAX_LIMIT));
        fileInterval = Integer.valueOf(preferences.getProperty(PPTISettings.FILE_INTERVAL));
        String publicKeyStr = preferences.getProperty(Settings.PUBLIC_KEY);
        String privateKeyStr = preferences.getProperty(Settings.PRIVATE_KEY);

        // Create PIR Client object
        he = new Paillier(keySize, rnd,publicKeyStr,privateKeyStr);
    }
    private void doHello() throws UnirestException{
        HttpResponse<String> response = Unirest.get( pptiServer + "ppti").asString();
        System.out.println(response.getBody());
    }
    private void getPreferences() throws UnirestException {
        preferences = new Properties();
        try (InputStream in = new FileInputStream(preferencesFile)) {
            preferences.load(in);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void deleteUserFile(UserFile userFile) throws UnirestException {

        HttpResponse<String> stringHttpResponse = Unirest.delete(pptiServer + "ufile")
                .header("accept", "application/json")
                .queryString("filename",userFile.getFileName())
                .asString();

        if(stringHttpResponse.getStatus() != 201) {
            System.out.println("Create User File Failed" + userFile.getFileName());
            System.exit(0);
        }
    }

    private void verifyResponse(UserFile responseFile) {
        HashMap<String, Double> cosSimMap;
        if(!responseFile.isPrivate()) {
            cosSimMap = responseFile.getCosSimMap();
        }
        else{
            HashMap<String, BigInteger> privateSQMap = responseFile.getPrivateSimQMap();
            cosSimMap = cosimpClient.extractPrivateResponse(responseFile.getFileName(),privateSQMap);
        }
        for (String fileName : cosSimMap.keySet()) {
            if(cosSimMap.get(fileName) > similarity & ! perfMeterStr.equals("on"))
                System.out.println(" User File " + responseFile.getFileName()+ " Spam File Name " + fileName + " Similarity " + cosSimMap.get(fileName));
        }
    }

    private UserFile getResponseUserFile(UserFile userFile) throws Exception {
        Gson gson = new Gson() ;
        HttpResponse<JsonNode> jsonHttpResponse = Unirest.get(pptiServer + "ufile")
                .header("accept", "application/json")
                .queryString("filename",userFile.getFileName())
                .asJson();

        if(jsonHttpResponse.getStatus() != 201) {
            System.out.println("Create User File Failed" + userFile.getFileName());
            System.exit(0);
        }
        final String response = jsonHttpResponse.getBody().toString();
        responseSize += response.getBytes("UTF-8").length;
        return gson.fromJson(response,(new TypeToken<UserFile>(){}.getType()));
    }
    private void resetAndLoad() throws UnirestException {

        HttpResponse<String> stringHttpResponse = Unirest.post(pptiServer + "limit")
                .header("accept", "application/json")
                .queryString(PPTISettings.FILE_MIN_LIMIT,String.valueOf(fileLimit))
                .asString();

        if(stringHttpResponse.getStatus() != 201) {
            System.out.println("Loading Files failed" + fileLimit);
            System.exit(0);
        }
    }

    private int createUserFiles(UserFile userFile) throws Exception {
        Gson gson = new Gson();
        String json = gson.toJson(userFile,(new TypeToken<UserFile>(){}.getType()));

        HttpResponse<String> stringHttpResponse = Unirest.post(pptiServer + "ufile")
                .header("accept", "application/json")
                .body(json)
                .asString();

        if(stringHttpResponse.getStatus() != 201) {
            System.out.println("Create User File Failed" + userFile.getFileName());
            System.exit(0);
        }
        return json.getBytes("UTF-8").length;
    }
    // Get All Spam Files For Trivial PIR
    private PerfMeter doTrivialPIRWithPerf() throws Exception {
        Gson gson = new Gson() ;
        PerfMeter perfMeter = new PerfMeter();

        try {
            long startTime = System.nanoTime();
            HttpResponse<JsonNode> allSpam = Unirest.get(pptiServer + "spamfiles").asJson();
            final String response = allSpam.getBody().toString();
            ArrayList<SpamFile> allFiles = gson.fromJson(response, new TypeToken<ArrayList<SpamFile>>(){}.getType());
            COSIMP_ServerImpl serverCosimp = new COSIMP_ServerImpl(allFiles,he,similarity);
            perfMeter.prepareDB = TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS);
            perfMeter.responseSize = response.getBytes("UTF-8").length;

            startTime = System.nanoTime();
            cosimpClient = new COSIMP_ClientImpl(inputDir, he, similarity, false,fileLimit);
            perfMeter.queryGen = TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS);

            startTime = System.nanoTime();
            for(SpamFile spamFile : serverCosimp.getSpamFiles()) {
                String serverFileName = spamFile.getFileName();
                spamFile.setTfIdfVector();
                spamFile.setMagnitude();
                for (UserFile clientFile : cosimpClient.getUserFiles()) {
                    String clientFileName = clientFile.getFileName();
                    double cosim =  serverCosimp.cosineSimilarity(clientFile, spamFile);
                    if(Math.floor(cosim) > similarity && !perfMeterStr.equals("on")) {
                        System.out.println(serverFileName + " " + clientFileName + " are similar " + cosim);
                    }
                }
            }
           perfMeter.processQuery = (TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS))/cosimpClient.getUserFiles().size();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return perfMeter;
    }

    // Check Spam Intelligence With Privacy
    private PerfMeter doCOSIMPWithPerf(boolean isPrivate) throws Exception {
        PerfMeter perfMeter = new PerfMeter();
        long startTime = System.nanoTime();
        try {
            cosimpClient = new COSIMP_ClientImpl(inputDir, he, similarity, isPrivate,fileLimit);

            if(isPrivate)
                getSpamMagnitudeMap();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Could not create COSIMP Client ");
        }

        ArrayList<UserFile> userFiles = cosimpClient.getUserFiles();

        // Create User Files
        int size = 0 ;
        for(UserFile userFile:userFiles) {
            if (isPrivate) {  // Reset Words for Privacy
                userFile.setWordsInFile(new ArrayList<>());
                userFile.resetTfIdfVector();
            }
            size += createUserFiles(userFile);
        }
        perfMeter.queryGen = TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS);
        perfMeter.querySize =  size;

        // Retrieve User Files with Spam Disposition
        startTime = System.nanoTime();
        responseSize = 0;
        ArrayList<UserFile> respList = new ArrayList<>(userFiles.size());
        for(UserFile userFile:userFiles) {
            UserFile responseFile = getResponseUserFile(userFile);
            respList.add(responseFile);
        }
        perfMeter.processQuery = (TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS));

        // Verify the Spam Disposition locally
        startTime = System.nanoTime();
        for(UserFile responseFile:respList) {
            verifyResponse(responseFile);
        }
        perfMeter.processResponse = (TimeUnit.MILLISECONDS.convert(System.nanoTime() - startTime, TimeUnit.NANOSECONDS));


        // Delete User Files on the Server
        for(UserFile userFile:userFiles){
            deleteUserFile(userFile);
        }

        perfMeter.responseSize =  responseSize;

        return perfMeter;

    }
    // Get All Spam Files For Trivial PIR
    private void doTrivialPIR() throws UnirestException {
        Gson gson = new Gson() ;

        HttpResponse<JsonNode> allSpam = Unirest.get(pptiServer + "spamfiles").asJson();
        ArrayList<SpamFile> allFiles = gson.fromJson(allSpam.getBody().toString(), new TypeToken<ArrayList<SpamFile>>(){}.getType());

        try {

            COSIMP_ServerImpl serverCosimp = new COSIMP_ServerImpl(allFiles,he,similarity);
            cosimpClient = new COSIMP_ClientImpl(inputDir, he, similarity, false,fileLimit);

            for(SpamFile spamFile : serverCosimp.getSpamFiles()) {
                String serverFileName = spamFile.getFileName();
                for (UserFile clientFile : cosimpClient.getUserFiles()) {
                    String clientFileName = clientFile.getFileName();
                    double cosim =  serverCosimp.cosineSimilarity(clientFile, spamFile);
                    if(Math.floor(cosim) > similarity && !perfMeterStr.equals("on")) {
                        System.out.println(serverFileName + " " + clientFileName + " are similar " + cosim);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Check Spam Intelligence With Privacy
    private void doCOSIMP(boolean isPrivate) throws Exception {
        try {
            cosimpClient = new COSIMP_ClientImpl(inputDir, he, similarity, isPrivate,fileLimit);

            if(isPrivate)
                getSpamMagnitudeMap();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Could not create COSIMP Client ");
        }

        ArrayList<UserFile> userFiles = cosimpClient.getUserFiles();

        for(UserFile userFile:userFiles) {
            if (isPrivate)   // Reset Words for Privacy
                userFile.setWordsInFile(new ArrayList<>());

            // Create User Files
            createUserFiles(userFile);

            // Retrieve User Files with Spam Disposition
            UserFile responseFile = getResponseUserFile(userFile);

            // Verify the Spam Disposition locally
            verifyResponse(responseFile);

            // Delete User Files on the Server
            deleteUserFile(userFile);

        }

    }
    // Get Server Magnitude Map (Euclidean Distance) of Spam Files

    private void getSpamMagnitudeMap() throws UnirestException {
        Gson gson = new Gson() ;
        HttpResponse<JsonNode> edResponse = Unirest.get(pptiServer + "ed").asJson();

        HashMap<String,Double> serverMagMap = gson.fromJson(edResponse.getBody().toString(),(new TypeToken<HashMap<String,Double>>(){}.getType()));
        cosimpClient.setServerMagPerFile(serverMagMap);
    }

    private void printPerfMeter (PerfMeter trivMeter,PerfMeter noPrivMeter,PerfMeter privMeter){
        System.out.println("METRIC, COUNT,  TRIVIAL, NO PRIV, PRIVACY");
        System.out.println("PREPAREDB, "    +fileLimit+","+trivMeter.prepareDB +","+noPrivMeter.prepareDB+","+privMeter.prepareDB);
        System.out.println("QUERY GEN, "    +fileLimit+","+trivMeter.queryGen +","+noPrivMeter.queryGen+","+privMeter.queryGen);
        System.out.println("PROCESS QUERY, "+fileLimit+","+trivMeter.processQuery +","+noPrivMeter.processQuery+","+privMeter.processQuery);
        System.out.println("PROCESS RESP,  "+fileLimit+","+trivMeter.processResponse +","+noPrivMeter.processResponse+","+privMeter.processResponse);
        System.out.println("QUERY SIZE, "   +fileLimit+","+noPrivMeter.querySize +","+noPrivMeter.querySize+","+privMeter.querySize);
        System.out.println("RESP SIZE, "    +fileLimit+","+trivMeter.responseSize +","+noPrivMeter.responseSize+","+privMeter.responseSize);

    }
    public static void main(String args[]) throws Exception {

        if(args.length == 0)
            preferencesFile = "client.properties";
        else
            preferencesFile = args[0];

        PPTIClient client = new PPTIClient();
        client.doHello();       // Just print Header
        for(int limit = client.fileMinLimit ; limit <= client.fileMaxLimit; limit = limit+client.fileInterval) {
           // System.out.println("Iteration :" + limit/5);
            client.fileLimit = limit;
            // ReLoad files in Server
            // client.resetAndLoad(); // Fixing the limit on Server

            try{
                // Perform PPTI

                if (client.perfMeterStr.equals("on")) {
                   // System.out.println("Doing TRIVIAL PIR : ");
                    PerfMeter trivMeter = client.doTrivialPIRWithPerf();  // Get All Spam Mails and Check

                   // System.out.println("Doing NO PIR : ");
                    PerfMeter noPrivMeter = client.doCOSIMPWithPerf(false); // Check Without Privacy

                   // System.out.println("Doing COSIMP : ");
                    PerfMeter privMeter = client.doCOSIMPWithPerf(true);  // Check With Privacy

                    //System.out.println("Printing Performance Metrics : ");
                    client.printPerfMeter(trivMeter, noPrivMeter, privMeter);

                } else {
                    client.doTrivialPIR();  // Get All Spam Mails and Check
                    client.doCOSIMP(false); // Check Without Privacy
                    client.doCOSIMP(true);  // Check With Privacy
                }
            }catch (Exception ex){
                System.out.println("Exception in PPTI Client " + ex.getMessage());
            }
        }
        Unirest.shutdown();
    }

}
