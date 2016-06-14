package org.crypto.pir.psdr;

import com.google.gson.Gson;
import org.crypto.pir.server.COSIMP_ServerImpl;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
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
public class SpamPrefsService {

    private String propertiesFile;
    private COSIMP_ServerImpl cosimpServer;

   public SpamPrefsService(String propertiesFile, COSIMP_ServerImpl cosimpServer) {
        this.propertiesFile = propertiesFile;
        this.cosimpServer = cosimpServer;
    }

    Properties findAll(){
        Properties prop = new Properties();
        InputStream input = null;

        try {
            input = new FileInputStream(propertiesFile);
            // load a properties file
            prop.load(input);

        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return prop;
    }

    Properties createSetting(String body){
        Properties properties = new Gson().fromJson(body, Properties.class);
        OutputStream output = null;

        try {
            output = new FileOutputStream(propertiesFile);

            // save properties to project root folder
            properties.store(output, null);

        } catch (Exception io) {
            io.printStackTrace();
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        }
        return properties;
    }

    void resetFileLimit(String fileLimit) throws Exception {
        int limit = Integer.valueOf(fileLimit);
        cosimpServer.loadFiles(limit);
    }
}
