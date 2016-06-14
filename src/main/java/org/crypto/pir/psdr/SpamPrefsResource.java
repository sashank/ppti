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
import org.crypto.jpir.util.Settings;
import org.crypto.pir.util.PPTISettings;

import java.util.Properties;

import static spark.Spark.get;
import static spark.Spark.post;

public class SpamPrefsResource {
    private static final String API_CONTEXT = "/";

    private final SpamPrefsService prefsService;

   public SpamPrefsResource(SpamPrefsService prefsService) {
        this.prefsService = prefsService;
        setupEndPoints();
    }

    private void setupEndPoints() {
        Gson gson = new Gson();
        post(API_CONTEXT + "/settings", "application/json", (request, response) -> {
            Properties props =  prefsService.createSetting(request.body());
            response.status(201);
            return gson.toJson(props);
        });

        get(API_CONTEXT + "/settings", "application/json", (request, response)

                ->{ Properties props = prefsService.findAll();
            response.status(201);
            return gson.toJson(props);
        });

        post(API_CONTEXT + "/limit", "application/json", (request, response) -> {
            try {
                prefsService.resetFileLimit(request.queryParams(PPTISettings.FILE_MIN_LIMIT));
                response.status(201);
            }catch (Exception e){
                response.status(500);
            }
            return response;
        });
    }
}
