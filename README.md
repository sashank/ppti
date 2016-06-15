
**Privacy Preserving Threat Intelligence**

----------
PPTI is research project.

As modern threats become more sophisticated, it is imperative for organizations to defend with the global
context. Many cloud based services provide threat intelligence pertaining to modern advanced persistent
threats (APTs). Cloud services such as: Google Safe Browsing, PhishTank, and Malwr offer black lists of
known malicious URLs, domains, emails etc. Querying such services require users to share their browsing
history and files in order to know whether their machines got infected or not. One of the major concerns/
hindrances remained to be addressed to benefit from such services is the users’ privacy.

Current implementation of PPTI has only Private Similar Document Retrieval(PSDR) scheme called COSIMP.
PPTI uses JPIR library (https://github.com/sashank/jpir)

The complete paper would be made available soon.

REST based Client/Server communication is supported for private queries

**Usage :**

**JPIR Setup :**

Download or git clone the project JPIR
change directory to jpir
Run the below command on your terminal to generate PIRServer.jar

    mvn clean install
    mv target/jpir-1.0-SNAPSHOT-jar-with-dependencies.jar PIRServer.jar

**PPTI Server Setup :**

Download or git clone the project PPTI
change directory to PPTI and configure pom.xml with jpir.jar's location
Run the below command on your terminal to generate PPTIServer.jar

    mvn clean install
    mv target/ppti-1.0-SNAPSHOT-jar-with-dependencies.jar PPTIServer.jar

 1. Copy the `PPTIServer.jar` file to some server.
 2. Copy the `server.properties` to the server
 3. Modify the server.properties with appropriate input file (as database)
 4. Run the below command to start the server
	  `java -jar PPTIServer.jar`

**Client Setup :**

 5. Update the `client.properties` with Server's IP Address 
 6. From your IDE just run the *PIR_RestClient.java*
 7. For running it from command line
	 8.  Change the `main` file in `pom.xml` with `PPTIClient`
	 9.   `mvn clean install`
	 10. `mv target/ppti-1.0-SNAPSHOT-jar-with-dependencies.jar PPTIClient.jar`
	 11. `java -jar PPTIClient.jar`   (Will execute the client)
The output would be printed on the console.
