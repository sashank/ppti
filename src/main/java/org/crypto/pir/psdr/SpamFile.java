package org.crypto.pir.psdr;

import org.apache.tika.Tika;

import java.io.File;
import java.util.ArrayList;
import java.util.StringTokenizer;

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
public class SpamFile {
    private String fileName;
    private ArrayList<String> wordsInFile = new ArrayList<>();
    private ArrayList<Integer> tfIdfVector = new ArrayList<>();
    private Double magnitude = 0.0;
    private Integer sqMagnitude = 0;

    public SpamFile(File file) {
        this.fileName = file.getName();
        try {
            init(file);
        } catch (Exception e) {
            System.out.println("Failed Init Spam File");
            e.printStackTrace();
        }
    }

    public SpamFile(String fileName){
        this.fileName = fileName;
    }
    private void init(File file) {

        try {
            Tika tika = new Tika();
            String type = tika.detect(file);
            String text = tika.parseToString(file);

            if (text.contains("Content-Type: text/plain"))  // Remove Header if any
                text = text.split("Content-Type: text/plain")[1];

            StringTokenizer st = new StringTokenizer(text);
            while (st.hasMoreElements()) {
                String word = String.valueOf(st.nextElement());
                       /* System.out.println(word);
                        if (!allTerms.contains(word)) {  //avoid duplicate entry
                            allTerms.add(word);
                        }*/
                wordsInFile.add(word);
            }

            if(wordsInFile.size() > 0) {
                setTfIdfVector();
                setMagnitude();
            }
        } catch (Exception e) {
            System.out.println("Some Exception reading the file"+file.getName());
            resetTfIdfVector();
            setMagnitude();
        }
    }
    public String getFileName() {
        return fileName;
    }

    public ArrayList<String> getWordsInFile() {
        return wordsInFile;
    }

    public void setWordsInFile(ArrayList<String> wordsInFile) {
        this.wordsInFile = wordsInFile;
        if(wordsInFile.size() > 0) {
            setTfIdfVector();
            setMagnitude();
        }
        else{
            tfIdfVector = new ArrayList<>();
            magnitude = 0.0;
        }
    }

    public Integer getSqMagnitude() {
        return sqMagnitude;
    }

    public ArrayList<Integer> getTfIdfVector() {
        return tfIdfVector;
    }

    public void setTfIdfVector() {
        int tf; //term frequency
        //  double idf; //inverse document frequency
        double tfidf; //term frequency inverse document frequency
        for (String term : wordsInFile) {
            tf = tfCalculator( term);
            // idf = idfCalculator(allTerms, term);
            // idf = 1.0d;
            // tfidf = tf * idf;
            tfIdfVector.add(tf);
        }
    }
    public void resetTfIdfVector() {
        tfIdfVector = new ArrayList<>();
    }

    public Double getMagnitude() {
        return magnitude;
    }

    public void setMagnitude() {
        Integer distance = 0 ;

        for(Integer i : tfIdfVector)
            distance += i * i ;

        this.magnitude = Math.sqrt(distance);
        this.sqMagnitude = distance;
    }
    private int tfCalculator(String termToCheck) {
        int count = 0;  //to count the overall occurrence of the term termToCheck
        for (String s : wordsInFile) {
            if (s.equalsIgnoreCase(termToCheck)) {
                count++;
            }
        }
        // return count / wordsInFile.size();
        return count ;
    }

    private  double idfCalculator(ArrayList<String> allTerms, String termToCheck) {
        double count = 0;
        for (String s : allTerms) {
            if (s.equalsIgnoreCase(termToCheck)) {
                count++;
                break;
            }
        }
        return Math.log(allTerms.size() / count);
    }
}
