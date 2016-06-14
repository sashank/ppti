package org.crypto.pir.psdr;

import org.crypto.jpir.crypto.HE;

import java.math.BigInteger;
import java.util.ArrayList;

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

public class COSIMP
{

    protected ArrayList<UserFile> userFiles = new ArrayList<>();
    private ArrayList<String> allTerms = new ArrayList<>(); //to hold all terms not needed without IDF
    protected String inputDir;
    protected   String spamDir = "spam/";
    protected   String usrDir = "user/";
    protected   String outDir = "out/";
    protected HE he;
    protected Double similarity;

    public COSIMP( HE enc, Double similarity) throws Exception {
            he = enc;
            this.similarity = similarity;
    }

    public String getInputDir() {
        return inputDir;
    }

    public Integer sq(ArrayList<Integer> v1, ArrayList<Integer> v2){
        Integer dotProduct = 0;

        for (int i = 0; i < v1.size(); i++)
            if(i < v2.size())
                dotProduct += v1.get(i) * v2.get(i);  //a.b

        return dotProduct;
    }

    /*
       Cipher TF-IDF - Is provided by Client
       Server TF-IDF - Is provided by Server
     */
    public BigInteger privateSq(ArrayList<BigInteger> cipherTFIDF, ArrayList<BigInteger> plainTFIDF){
        BigInteger dotProduct = new BigInteger("0");
        for (int i = 0; i < cipherTFIDF.size(); i++) {
            if (i < plainTFIDF.size()) {
                BigInteger product =   he.multiplyByScalar(cipherTFIDF.get(i), plainTFIDF.get(i));  //a.b
                if( i == 0)
                    dotProduct = product;
                else
                    dotProduct = he.add(dotProduct,product);
            }
        }
        return dotProduct;
    }


    public double cosineSimilarity(UserFile userFile, SpamFile spamFile) {
        double dotProduct;
        double magnitude1;
        double magnitude2;
        double cosineSimilarity;

        dotProduct = sq(userFile.getTfIdfVector(),spamFile.getTfIdfVector());

        magnitude1 = userFile.getMagnitude();
        magnitude2 = spamFile.getMagnitude();

        if (dotProduct == -1)
            cosineSimilarity = -1;
        else if (magnitude1 != 0.0 || magnitude2 != 0.0)
            cosineSimilarity = ( dotProduct / (magnitude1 * magnitude2));
        else
            cosineSimilarity = 0.0;

        return (cosineSimilarity);
    }

   public double cosineSimilarity(Integer sq, double mag1, double mag2){
        return  sq / (mag1 * mag2);
    }

}

