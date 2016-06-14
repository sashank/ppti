package org.crypto.pir.psdr;

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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;
import java.util.HashMap;

import static spark.Spark.*;

public class SpamDetectResource {
    private static final String API_CONTEXT = "/";

    private final SpamDetectService spamDetectService;

    public SpamDetectResource(SpamDetectService spamDetectService) {
        this.spamDetectService = spamDetectService;
        setupEndPoints();
    }
    private void setupEndPoints() {
        Gson gson = new Gson();

        // Get All Magnitudes (Euclidean Distance) ed of all Spam Files
        get(API_CONTEXT + "/ed", "application/json", (request, response)
                ->{ HashMap<String,Double> map = spamDetectService.getAllMagnitudes();
            response.status(201);
            return gson.toJson(map);
        });

        // Get All Spam Files
        get(API_CONTEXT + "/spamfiles", "application/json", (request, response) ->{
           // System.out.println("Retrieving All Files");
            ArrayList<SpamFile> list = spamDetectService.findAll();
            response.status(201);
            return gson.toJson(list);
        });

        // CRUD Operations for User Files

        // User File Creation for Comparing Spam Intelligence
        post(API_CONTEXT + "/ufile", "application/json", (request, response) -> {
           // System.out.println("Creating User File");
            spamDetectService.createUserFile(request.body());
            response.status(201);
            return response;
        });

        //Retrieve User File for Checking Spam Intelligence Verdict
        get(API_CONTEXT + "/ufile", "application/json", (request, response)
                ->{ UserFile userFile = spamDetectService.getUserFile(request.queryParams("filename"));
            response.status(201);
            return gson.toJson(userFile, (new TypeToken<UserFile>(){}.getType()));
        });

        //Delete User Files after getting the verdict
        delete(API_CONTEXT + "/ufile", "application/json", (request, response)
                ->{ spamDetectService.deleteUserFile(request.queryParams("filename"));
            response.status(201);
            return response;
        });

    }
}
