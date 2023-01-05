// Simple JMX scanner extracting data (IP:Port) from RMI Registry and verifying RCE (using MLet) exploitability without credentials.
// Version: 0.1
// Author: Marcin Wolak
// LinkedIn: https://www.linkedin.com/in/marcinwolak/
// Medium: https://marcin-wolak.medium.com/
// Github: https://github.com/marcin-wolak/
// Tested successfuly against JMX enabled on Java x64:
// Java(TM) SE Runtime Environment (build 1.7.0_80-b15) on Windows 10
// Java(TM) SE Runtime Environment (build 1.8.0_202-b08) on Windows 10
// Java(TM) SE Runtime Environment (build 9.0.4+11) on Windows 10
// OpenJDK Runtime Environment (build 11.0.17+8-post-Ubuntu-1ubuntu222.04)
// OpenJDK Runtime Environment (build 17.0.5+8-Debian-2)

import java.net.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System;
import java.util.*;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.HelpFormatter;


public class SimpleRmiDiscoverer {

// IP Address of the RMI Registry to query (CMD Parameter)
private String regIP;
// TCP Port of the RMI Registry to query (CMD Parameter)
private int regPort;
// Ignore endpoint from RMI Registry to verify exploitability without credentials. Use instead IP of the registry itself and dynamic TCP port from the registry dump (CMD Parameter)
private boolean ignoreEndpoint;
// Extract Host:Port from the RMI Registry without checking RCE exploitability without credentials (CMD Parameter)
private boolean dumpOnly;

// IP Address and TCP port for the endpoint exposed via RMI Registry
private String endPIP;
private int endPPort;

// Sockets for communication with RMI Registry and exposed endpoint
private Socket regS;
private Socket endPS;

//Streams for communication via above sockets
private InputStream in, inEndP;
private OutputStream out, outEndP;

// RMI Handshake data
private byte[] hShake1 ={0x4A,0x52,0x4D,0x49,0x00,0x02,0x4B};
private byte[] hShake2 ={0x00,0x09,0x31,0x32,0x37,0x2E,0x30,0x2E,0x30,0x2E,0x31,0x00,0x00,0x00,0x00};

// Calling Obj
private byte[] hObj ={0x50,(byte)0xac,(byte)0xed,0x00,0x05,0x77,0x22,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x44,0x15,0x4d,(byte)0xc9,(byte)0xd4,(byte)0xe6,0x3b,(byte)0xdf,0x74,0x00,0x06,0x6a,0x6d,0x78,0x72,0x6d,0x69};


//Pattern to find in dumped registry (UnicastRef)
private byte[] ucRef = {0x55,0x6e,0x69,0x63,0x61,0x73,0x74,0x52,0x65,0x66};

//Pattern to find in exception dump (Credentials required)
private byte[] credReq = {(byte)0x43,(byte)0x72,(byte)0x65,(byte)0x64,(byte)0x65,(byte)0x6e,(byte)0x74,(byte)0x69,(byte)0x61,(byte)0x6c,(byte)0x73,(byte)0x20,(byte)0x72,(byte)0x65,(byte)0x71,(byte)0x75,(byte)0x69,(byte)0x72,(byte)0x65,(byte)0x64};

// Calling Obj (after modification) on the dynamic port  
private byte[] hDObj ={(byte)0x50,(byte)0xac,(byte)0xed,(byte)0x00,(byte)0x05,(byte)0x77,(byte)0x22,(byte)0x6d,(byte)0xf9,(byte)0xa5,(byte)0x39,(byte)0xb4,(byte)0xfa,(byte)0x06,(byte)0xc3,(byte)0xea,(byte)0x8e,(byte)0xa7,(byte)0x0e,(byte)0x00,(byte)0x00,(byte)0x01,(byte)0x85,(byte)0x06,(byte)0x13,(byte)0xa1,(byte)0x4d,(byte)0x80,(byte)0x01,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xf0,(byte)0xe0,(byte)0x74,(byte)0xea,(byte)0xad,(byte)0x0c,(byte)0xae,(byte)0xa8,(byte)0x70};

private String endpIP;
private short enpPort;

//javax.management.remote.rmi.RMIServerImpl_Stub object details collected from RMI registry:
private byte[] rmiStub;
int rmiStubLength;
int eIPlength;
byte [] eIP;
byte [] ePort;

// Constructor. Parameter dumps determines if only dynamic endpoint should be extracted from RMI Registry without checking if JMX is username/password protected
// Ignore detrmines if the IP of endpoint extracted from registry should be ignored and the IP of RMI Registry used instead
public SimpleRmiDiscoverer(String rIP, int rPort, boolean ignore, boolean dump) {
		regPort = rPort;
		regIP = rIP;
		rmiStub = new byte[4096];
		ignoreEndpoint = ignore;
                dumpOnly = dump;
}

// findArray taken from: https://stackoverflow.com/questions/3940194/find-an-array-inside-another-larger-array
    public int findArray(byte[] largeArray, byte[] subArray) {

        /* If any of the arrays is empty then not found */
        if (largeArray.length == 0 || subArray.length == 0) {
            return -1;
        }

        /* If subarray is larger than large array then not found */
        if (subArray.length > largeArray.length) {
            return -1;
        }

        for (int i = 0; i < largeArray.length; i++) {
            /* Check if the next element of large array is the same as the first element of subarray */
            if (largeArray[i] == subArray[0]) {

                boolean subArrayFound = true;
                for (int j = 0; j < subArray.length; j++) {
                    /* If outside of large array or elements not equal then leave the loop */
                    if (largeArray.length <= i+j || subArray[j] != largeArray[i+j]) {
                        subArrayFound = false;
                        break;
                    }
                }

                /* Sub array found - return its index */
                if (subArrayFound) {
                    return i;
                }

            }
        }

        /* Return default value */
        return -1;
    }

// Connecting to RMI Registry using IP/TCP pair from CLI 
private int connectRegistry()
{
	try {
		//System.out.println("IP: " + regIP);
		regS = new Socket(regIP, regPort);
		in = this.regS.getInputStream();
        	out = this.regS.getOutputStream();
	}
	catch (Exception e) {
		System.out.println("[!] Cannot connect to RMI Registry.");
		//e.printStackTrace();
		return 0;
        }
        return 1;
}

// RMI handshake. Common function for handshaking with RMI Registry as well as the endpoint extracted from it 
private int rmiHandShake(InputStream inP, OutputStream outP)
{
	byte [] buffer = new byte[4096];
	try {
		outP.write(hShake1, 0, hShake1.length);
		int count = inP.read(buffer);
		if(count==0)
		{
			System.out.println("[!] Handshake failed, no date received. Likely not RMI.");
			return -1;
		}
		else
		{
		  if(buffer[0]!=0x4E)
		  {
		   	System.out.println("[!] Handshake failed, bad response. Likely not RMI.");
			return -2;
		  }
		  outP.write(hShake2, 0, hShake2.length);
		}
	}
	catch (Exception e) {
		System.out.println("[!] Handshake failed, Error in RMI Communication.");
            	//e.printStackTrace();
            	return 0;
        }
	return 1;
}

// Invoking RMIServerImpl_Stub over RMI Registry
private int invokeObject()
{
	try {
		out.write(hObj, 0, hObj.length);
		int rmiStubLength = in.read(rmiStub);
		if(rmiStubLength==0)
		{
			System.out.println("[-] RMIServerImpl_Stub invocation against RMI Registry failed, no response!");
			return -1;
		}
		//String s = new String(rmiStub);
		//System.out.println(s);
		//Findinf "UnicastRef" in the response from RMI Registry:
		int unipos = findArray(rmiStub, ucRef);
		if(unipos<1)
		{
		 System.out.println("[-] RMIServerImpl_Stub invocation against RMI Registry failed, Malformed registry dump.");
		 return -2;
		}
		//else
		// System.out.println("\nThe position is: " + unipos);
		eIPlength = (int) rmiStub[unipos+11];
		//System.out.println("\nLength of eIP is: " + eIPlength);
		eIP = Arrays.copyOfRange(rmiStub,unipos+12,unipos+12+eIPlength);
		endPIP = new String(eIP);
		//System.out.println("\nThe eIP is: " + endPIP);
		ePort = Arrays.copyOfRange(rmiStub,unipos+12+eIPlength,unipos+16+eIPlength);
		DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(ePort));
		endPPort = inputStream.readInt();
		//System.out.println(endPPort);
		//System.out.println("\nThe ePort is: " + Integer.valueOf(new String(ePort)));
	}
	catch (Exception e) {
		System.out.println("[-] RMIServerImpl_Stub invocation against RMI Registry failed, Other Error.");
            	// e.printStackTrace();
            	return 0;
        }
	return 1;
}

// Connecting to the endpoint extracted from RMI registry or (when ignore option active) to RMI Registry IP and TCP port extracted from this Registry.
private int connectEndPoint(boolean ignoreEndPoint)
{
	try {
		//System.out.println("End Point IP: " + endPIP);
		//System.out.println("End Point Port: " + endPPort);
		System.out.println("[+] Connecting to the dynamic Endpoint ... ");
		if(!ignoreEndPoint){
			endPS = new Socket(endPIP, endPPort);
		}
		else
		{
			System.out.println("[+] Ignoring the endpoint exposed on: " + endPIP);
			System.out.println("[+] Connecting instead to: " + regIP + " on TCP Port:" + Integer.toString(endPPort));
			endPS = new Socket(regIP, endPPort);
		}
		inEndP = this.endPS.getInputStream();
        	outEndP = this.endPS.getOutputStream();
	}
	catch (Exception e) {
            // e.printStackTrace();
            System.out.println("[-] Connection to the dynamic Endpoint failed!");
            return 0;
        }
        System.out.println("[+] Dynamic Endpoint connected successfuly!");
        return 1;
}

// Invoking RMIServerImpl_Stub over the endpoint extracted from RMI registry or (when ignore option active) over RMI Registry IP and TCP port extracted from this Registry.
private int invokeDObject()
{
	int unipos = findArray(rmiStub, ucRef);
	System.arraycopy(rmiStub, unipos + 16 + endPIP.length(), hDObj, 7, 8);
	System.arraycopy(rmiStub, 8, hDObj, 15, 4);
	System.arraycopy(rmiStub, 16, hDObj, 23, 4);
	byte [] buffer = new byte[4096];
	try {
		outEndP.write(hDObj, 0, hDObj.length);
		int dStubLength = inEndP.read(buffer);
		if(dStubLength==0)
		{
			System.out.println("[-] Invoking RMIServerImpl_Stub on the dynamic Endpoint failed, no response.");
			return -1;
		}
		String s = new String(buffer);
		if(s.contains("Credentials required")){
			System.out.println("[-] Dynamic Enpoint requires credentials (username and password).");
		}
		else if(s.contains("UnicastRef")){
			System.out.println("[+] Dynamic Enpoint is VULNERABLE to RCE, NO username and password required.");
		}
		else {
			System.out.println("[-] Unknown outcome from invoking RMIServerImpl_Stub on the dynamic Endpoint. See below:");
			System.out.println(s);
		}
	}
	catch (Exception e) {
		e.printStackTrace();
            	return 0;
        }
	return 1;
}

private void closeSocket(Socket inSock){
		
		try{
        	inSock.close();}
        	catch (Exception e) {
            		//e.printStackTrace();
            	}

}

public static void main(String[] args) throws Exception{

	boolean ignore=false;
	boolean donly=false;
	String IP = "";
	long Port = 1099;
	Options options = new Options();
	options.addOption("h", "help", false, "Prints help for the tool.");
	options.addOption("i", "ignore", false, "Uses RMI registry IP for methods invocations. Ignores endpoint from the Registry dump.");
	options.addOption("d", "dumponly", false, "Extracting endpoint <host:port> from RMI Registry without checking exploitabilty, which is by default checked.");
	options.addOption(OptionBuilder.withLongOpt("host").withDescription("IP of RMI Registry to query.").hasArg().withArgName("RMI HOST IP ").isRequired().create("H"));
	options.addOption(OptionBuilder.withLongOpt("port").withDescription("TCP port of RMI Registry to query.").hasArg().withArgName("RMI HOST TCP PORT ").isRequired().create("P"));
	//options.addOption("H", "--host", false, "IP of RMI Registry to query.");
	//options.addOption("P", "--port", false, "TCP port of RMI Registry.");
	CommandLineParser parser = new DefaultParser();
	
	String header = "SimpleRmiDiscoverer extracts JMX host:port endpoint from RMI registry and checks if is exploitable without credentials using MLet.\n\n";
        String footer = "\nPlease check my Blog for more details: https://marcin-wolak.medium.com/";

 	HelpFormatter formatter = new HelpFormatter();
 	
	
	try {
    		CommandLine cmd = parser.parse(options, args);
    		if (cmd.hasOption("h")) {
  			formatter.printHelp("SimpleRmiDiscoverer", header, options, footer, true);
  			System.exit(0);
  		}
  		if (cmd.hasOption("i")) {
  			ignore = true;
  		}
  		if (cmd.hasOption("d")) {
  			donly = true;
  		}
  		if (cmd.hasOption("H")) {
  			IP = cmd.getOptionValue("H");
  		}
  		if (cmd.hasOption("P")) {
  			try {
  				Port = Long.valueOf(cmd.getOptionValue("P")); }
  			catch (Exception e){
  				System.out.println(e.getMessage());
  				System.out.println("[!] Parameter -P --port must be a number between 1 and 65535!\n\n");
  				formatter.printHelp("SimpleRmiDiscoverer", header, options, footer, true);
  				System.exit(1);
  			}
  			if(Port<0 || Port>65535){
  				System.out.println("[!] Parameter -P --port out of range!\n\n");
  				formatter.printHelp("SimpleRmiDiscoverer", header, options, footer, true);
  				System.exit(0);
  			}
  			
  		}
  		
  	} catch (ParseException e){
  		System.out.println(e.getMessage());
  		formatter.printHelp("SimpleRmiDiscoverer", header, options, footer, true);
  		System.exit(1);
		
	}

	System.out.println("[+] Approached RMI Registry IP: " + IP);
	System.out.println("[+] Approached RMI Registry TCP Port: " + Port);
	
	SimpleRmiDiscoverer sRD = new SimpleRmiDiscoverer(IP, (int) Port, ignore, donly);
	sRD.start();
    }
    
public int start() {
        // can now access non-static fields
        int isConnected = connectRegistry();
        if(isConnected == 0){
        	System.out.println("[-] Aborting Connection to RMI Registry! Quiting!");
        	closeSocket(regS);
        	return -1;
        }
        int isHShaked = rmiHandShake(in,out);
        if(isHShaked != 1){
        	System.out.println("[-] Aborting handShaking with RMI Registry! Quiting!");
        	closeSocket(regS);
        	return -2;
        }
        int isInvoked = invokeObject();
        if(isInvoked != 1){
        	System.out.println("[-] Object Calling Error, RMI Registry! Quiting");
        	closeSocket(regS);
        	return -2;
        }
        
        System.out.println("[+] RMI Registry contacted successfuly!");
        System.out.println("[+] Extracted Endpoint Name / IP Address: " + endPIP);
        System.out.println("[+] Extracted Endpoint Dynamic TCP Port: " + endPPort);
        
        closeSocket(regS);
        
        if(dumpOnly)
        {
        	System.out.println("[+] RMI Registry Dump Completed Successfuly!");
        	System.exit(0);
        }
        
        int isEConnected = connectEndPoint(ignoreEndpoint);
        if(isEConnected != 1){
        	System.out.println("[-] Aborting!");
        	closeSocket(endPS);
        	return -3;
        }
        isHShaked = rmiHandShake(inEndP, outEndP);
        if(isHShaked != 1){
        	System.out.println("[-] Cannot handShake with the dynamic Endpoint!");
        	closeSocket(endPS);
        	return -2;
        }
        int isDInvoked = invokeDObject();
        if(isDInvoked != 1){
        	System.out.println("[-] Cannot Invoke RMIServerImpl_Stub on the dynamic Endpoint!");
        	closeSocket(endPS);
        	return -4;
        }
        closeSocket(endPS);
        return 1;
    }
    
}
