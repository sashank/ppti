package org.crypto.pir.client;

import org.crypto.jpir.crypto.HE;
import org.crypto.pir.psdr.COSIMP;
import org.crypto.pir.psdr.UserFile;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

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
public class COSIMP_ClientImpl extends COSIMP {
    private HashMap<String,Double> serverMagPerFile = new HashMap<>();
    private boolean isPrivate;
    private int fileLimit;
    public COSIMP_ClientImpl(String inputDir, HE he, Double similarity, boolean isPrivate, int limit) throws Exception {
        super(he, similarity);
        this.inputDir = inputDir;
        this.isPrivate = isPrivate;
        this.fileLimit = limit;
        loadFiles();
    }

    private void loadFiles() {
        File dataDir =  new File( inputDir + spamDir);
        File[] fileList =  dataDir.listFiles();
        if(fileList == null) {
            System.err.println("Data File List is empty in :"+dataDir.getPath());
            System.exit(0);
        }
        else {
            for(int i= 0; i < fileList.length ; i++) {
                if(i <= fileLimit) {
                    File file = fileList[i];
                    UserFile spamFile = new UserFile(file,isPrivate);
                    userFiles.add(spamFile);
                }
                else
                    break; //Don't process beyond files limit;
            }
            if(isPrivate)
                privateQueryGen();
        }
    }
    private void privateQueryGen() {

        for(UserFile userFile : userFiles) {
                ArrayList<BigInteger> privateQuery = new ArrayList<>();
                ArrayList<Integer> tfIdfVector = userFile.getTfIdfVector();
                for (Integer tfidf : tfIdfVector) {
                    BigInteger bigInteger = new BigInteger(String.valueOf(tfidf));
                    BigInteger privateTFIDF = he.encrypt(bigInteger);
                    privateQuery.add(privateTFIDF);
                }
                userFile.setPrivateTfIdfVector(privateQuery);
        }
    }

    public void setServerMagPerFile(HashMap<String,Double> serverMagPerFile){
        this.serverMagPerFile = serverMagPerFile;
    }

    public ArrayList<UserFile>  getUserFiles(){
        return userFiles;
    }

    public HashMap<String,Double> extractPrivateResponse(String fileName, HashMap<String,BigInteger> privateResponseMap) {
        UserFile userFile = getUserFile(fileName);
        HashMap<String,Double> response = new HashMap<>();
        for(String serverFile: privateResponseMap.keySet()) {
            BigInteger bigResponse = he.decrypt(privateResponseMap.get(serverFile));
            Integer resp = bigResponse.intValue();
            double sim = cosineSimilarity(resp,userFile.getMagnitude(),serverMagPerFile.get(serverFile));
            if(sim >= similarity) {
              //  System.out.println("Similarity between " + fileName + " " + serverFile + " is " + sim);
                response.put(serverFile,sim);
            }
        }
        return response;
    }
    public UserFile getUserFile(String fileName){
        for(UserFile userfile:userFiles){
            if(userfile.getFileName().equals(fileName)) {
                return userfile;
            }
        }
        return new UserFile(new File(fileName), false);
    }
}
