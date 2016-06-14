package org.crypto.pir.psdr;

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
public class UserFile extends SpamFile {
    private HashMap<String,BigInteger> pSimQMap; // Private Similarity Quotient with each spam file
    private HashMap<String,Double> cosSimMap; // Cossine Similarity with each spam file
    private ArrayList<BigInteger> privateTfIdfVector; // Private TF IDF Vector
    private boolean isPrivate; // Is Private Instance of User File ?
    private BigInteger privateMagnitude ;
    public UserFile(File file, boolean isPrivate) {
        super(file);
        this.isPrivate = isPrivate;
    }

    public boolean isPrivate() {
        return isPrivate;
    }

    public UserFile(String fileName) {
        super(fileName);
    }

    public HashMap<String, BigInteger> getPrivateSimQMap() {
        return pSimQMap;
    }

    public void setpSimQMap(HashMap<String, BigInteger> pSimQMap) {
        this.pSimQMap = pSimQMap;
    }

    public HashMap<String, Double> getCosSimMap() {
        return cosSimMap;
    }

    public void setCosSimMap(HashMap<String, Double> cosSimMap) {
        this.cosSimMap = cosSimMap;
    }

    public ArrayList<BigInteger> getPrivateTfIdfVector(){return privateTfIdfVector;};

    public void setPrivateTfIdfVector(ArrayList<BigInteger> privateTfIdfVector){
        this.privateTfIdfVector = privateTfIdfVector;
    }
}
