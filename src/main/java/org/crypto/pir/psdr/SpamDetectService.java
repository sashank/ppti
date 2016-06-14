package org.crypto.pir.psdr;

import com.google.gson.Gson;
import org.crypto.pir.server.COSIMP_ServerImpl;

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
public class SpamDetectService {

    private COSIMP_ServerImpl cosimpServer;

    public SpamDetectService(COSIMP_ServerImpl cosimpServer) {
        this.cosimpServer = cosimpServer;
    }

    ArrayList<SpamFile> findAll(){
        ArrayList<SpamFile> respList = new ArrayList<>();
        for(SpamFile spamFile : cosimpServer.getSpamFiles()) {
            spamFile.resetTfIdfVector();// For bandwidth Optimization
           respList.add(spamFile);
        }
        return respList;
    }

    HashMap<String, Double> getAllMagnitudes(){
        HashMap<String, Double> map = new HashMap<>();
        ArrayList<SpamFile> spamFiles = cosimpServer.getSpamFiles();
        for(SpamFile spamFile: spamFiles){
            map.put(spamFile.getFileName(),spamFile.getMagnitude());
        }
        return map;
    }

    void createUserFile(String body){
       UserFile userFile = new Gson().fromJson(body, UserFile.class);
       cosimpServer.addUserFile(userFile);
    }

    UserFile getUserFile(String fileName){
        UserFile userFile = cosimpServer.getUserFile(fileName);

        if(!userFile.isPrivate())
            userFile.setCosSimMap(cosimpServer.processQuery(userFile));
        else
            userFile.setpSimQMap(cosimpServer.processPrivateQuery(userFile.getPrivateTfIdfVector()));

        userFile.resetTfIdfVector();
       return userFile;
    }

    void deleteUserFile(String fileName){
        cosimpServer.deleteUserFile(fileName);
    }
}
