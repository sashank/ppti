package org.crypto.pir.server;

import org.crypto.jpir.crypto.HE;
import org.crypto.pir.psdr.COSIMP;
import org.crypto.pir.psdr.SpamFile;
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
public class COSIMP_ServerImpl extends COSIMP {
    private ArrayList<SpamFile> spamFiles;

    public COSIMP_ServerImpl(String inputDir, HE he, Double similarity, int filesLimit) throws Exception {
        super(he, similarity);
        this.inputDir = inputDir;
        loadFiles(filesLimit);
    }

    public void loadFiles(int filesLimit) throws Exception{
        spamFiles = new ArrayList<>();
        File dataDir =  new File( inputDir + spamDir);
        File[] fileList =  dataDir.listFiles();
        if(fileList == null) {
            System.err.println("Data File List is empty in :"+dataDir.getPath());
        }
        else {
            for(int i= 0; i < fileList.length ; i++) {
                if(i <= filesLimit) {
                    File file = fileList[i];
                    SpamFile spamFile = new SpamFile(file);
                    spamFiles.add(spamFile);
                }
                else
                    break; //Don't process beyond files limit;
            }
        }
    }

    public COSIMP_ServerImpl(ArrayList<SpamFile> spamFiles, HE he, Double similarity) throws Exception {
        super(he, similarity);
        this.spamFiles = spamFiles;
    }
    public  ArrayList<BigInteger> getBigInteger(ArrayList<Integer> tfIdfVector) {
        ArrayList<BigInteger> bigIntegers = new ArrayList<>(tfIdfVector.size());
        for(Integer tfidf: tfIdfVector)
            bigIntegers.add(new BigInteger(String.valueOf(tfidf)));
        return bigIntegers;
    }

    public HashMap<String,BigInteger> processPrivateQuery(ArrayList<BigInteger> queryValues) {
        HashMap<String, BigInteger> resMap = new HashMap<>();
        for(SpamFile spamFile : spamFiles){
            ArrayList<Integer> tfIdfVector = spamFile.getTfIdfVector();
            ArrayList<BigInteger> bigVector = getBigInteger(tfIdfVector);
            BigInteger privateSq = privateSq(queryValues,bigVector);
            resMap.put(spamFile.getFileName(),privateSq);
        }
        return resMap;
    }
    public ArrayList<SpamFile>  getSpamFiles(){
        return spamFiles;
    }

    public HashMap<String,Double> processQuery(UserFile userFile) {
        Double cosim;
        HashMap<String,Double> response = new HashMap<>();
        for(SpamFile spamFile : spamFiles){
            cosim = cosineSimilarity(userFile,spamFile);
            if(cosim > similarity)
                response.put(spamFile.getFileName(),cosim);
        }
        return response;
    }

    public void addUserFile(UserFile userFile) {
        userFiles.add(userFile);
    }

    public void deleteUserFile(String fileName){
        for(UserFile userfile:userFiles){
            if(userfile.getFileName().equals(fileName)) {
                userFiles.remove(userfile);
                break;
            }
        }
    }
    public UserFile getUserFile(String fileName){
        for(UserFile userfile:userFiles){
            if(userfile.getFileName().equals(fileName)) {
                return userfile;
            }
        }
        return new UserFile(fileName);
    }

    public SpamFile getSpamFile(String fileName){
        for(SpamFile spamFile:spamFiles){
            if(spamFile.getFileName().equals(fileName)) {
                return spamFile;
            }
        }
        return new SpamFile(fileName);
    }
}
