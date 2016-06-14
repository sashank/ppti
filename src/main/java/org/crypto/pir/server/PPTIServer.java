package org.crypto.pir.server;

import org.crypto.jpir.crypto.HE;
import org.crypto.jpir.crypto.Paillier;
import org.crypto.jpir.util.Settings;
import org.crypto.pir.psdr.*;
import org.crypto.pir.util.PPTISettings;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Properties;

import static spark.Spark.get;
import static spark.Spark.port;

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

public class PPTIServer {
    private static SpamPrefsService prefsService ;
    private static  COSIMP_ServerImpl cosimpServer;
    private static  String preferencesFile;
    private static  String port;
    private static void init() {
        Properties properties;
        try (InputStream in = new FileInputStream(preferencesFile)) {
            properties = new Properties();
            properties.load(in);

            String cipher = properties.getProperty(Settings.CIPHER);
            int keySize = Integer.valueOf(properties.getProperty(Settings.KEYSIZE));
            SecureRandom rnd = new SecureRandom();
            String publicKeyStr =  properties.getProperty(Settings.PUBLIC_KEY);
            Double similarity = Double.valueOf(properties.getProperty(PPTISettings.SIMILARITY));
            String inputDir = properties.getProperty(Settings.INPUTDIR);
            int fileMaxLimit = Integer.valueOf(properties.getProperty(PPTISettings.FILE_MAX_LIMIT));
            port = properties.getProperty(Settings.SERVER_PORT);
            HE  he;
            if(cipher.equals(Settings.PAILLIER)) {
                he =  new Paillier(keySize,rnd,publicKeyStr,"");
                cosimpServer = new COSIMP_ServerImpl(inputDir, he, similarity, fileMaxLimit);
            }
            prefsService = new SpamPrefsService(preferencesFile,cosimpServer);
        } catch (IOException e) {
            e.printStackTrace();
        }   catch (Exception e) {
            e.printStackTrace();
            System.out.println("Cannot init COSIMP Server");
            System.exit(0);
        }
    }

    public static void main(String[] args) throws Exception {
        if(args.length == 0)
            preferencesFile = "server.properties";
        else
            preferencesFile = args[0];

        //Initialize
        init();

        port(Integer.parseInt(port));
        // Basic Home page Like
        get("/ppti", (request, response) -> "Privacy Preserving Threat Intelligence");

        new SpamPrefsResource(prefsService);

        new SpamDetectResource(new SpamDetectService(cosimpServer));
    }
}
