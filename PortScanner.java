/*
 * 
 * Author :	SAEED GHIASSY
 * 
 * 
 * Description: Connective mode port scanner 
 */
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
public class PortScanner {

	//static global variables
	private static String Hostname;
	private static String PortFrom , PortTill = "0";
	private static String FinalReport = "";
	private static int counter =0;
	//default time out on connections
	private static int myTIMEOUT= 1000;
	

	//Services name based on /etc/services in Linux
	private static final Map<Integer, String> MyServices = new HashMap<Integer, String>(){
		{
			put(1, "tcpmux");put(7, "echo");put(9, "discard");put(11, "systat");put(13, "daytime");
			put(15, "netstat");put(17, "qotd");put(18, "msp");put(19, "chargen");put(20, "ftp-data");
			put(21, "ftp");put(22, "ssh");put(23, "telnet");put(25, "smtp");put(37, "time");
			put(42, "nameserver");put(43, "whois");put(49, "tacacs");put(50, "re-mail-ck");
			put(53, "domain");put(57, "mtp");put(65, "tacacs-ds");put(67, "bootps");
			put(68, "bootpc");put(70, "gopher");put(77, "rje");put(79, "finger");put(80, "www");
			put(87, "link");put(88, "kerberos");put(95, "supdup");put(101, "hostnames");
			put(102, "iso-tsap");put(104, "acr-nema");put(105, "csnet-ns");put(107, "rtelnet");
			put(109, "pop2");put(110, "pop3");put(111, "sunrpc");put(113, "auth");put(115, "sftp");
			put(117, "uucp-path");put(119, "nntp");put(123, "ntp");put(129, "pwdgen");
			put(135, "loc-srv");put(137, "netbios-ns");put(138, "netbios-dgm");
			put(139, "netbios-ssn");put(143, "imap2");put(161, "snmp");
			put(162, "snmp-trap");put(163, "cmip-man");put(164, "cmip-agent");
			put(174, "mailq");put(177, "xdmcp");put(178, "nextstep");put(179, "bgp");
			put(191, "prospero");put(194, "irc");put(199, "smux");put(201, "at-rtmp");
			put(202, "at-nbp");put(204, "at-echo");put(206, "at-zis");put(209, "qmtp");
			put(210, "z3950");put(213, "ipx");put(220, "imap3");put(345, "pawserv");
			put(346, "zserv");put(347, "fatserv");put(369, "rpc2portmap");
			put(370, "codaauth2");put(371, "clearcase");put(372, "ulistserv");
			put(389, "ldap");put(406, "imsp");put(427, "svrloc");put(443, "https");
			put(444, "snpp");put(445, "microsoft-ds");put(464, "kpasswd");put(487, "saft");
			put(500, "isakmp");put(554, "rtsp");put(607, "nqs");put(610, "npmp-local");
			put(611, "npmp-gui");put(612, "hmmp-ind");put(628, "qmqp");put(631, "ipp");
			put(512, "exec");put(513, "login");put(514, "shell");put(515, "printer");
			put(526, "tempo");put(530, "courier");put(531, "conference");put(532, "netnews");
			put(538, "gdomap");put(540, "uucp");put(543, "klogin");put(544, "kshell");
			put(546, "dhcpv6-client");put(547, "dhcpv6-server");put(548, "afpovertcp");
			put(549, "idfp");put(556, "remotefs");put(563, "nntps");
			put(587, "submission");put(636, "ldaps");put(655, "tinc");
			put(706, "silc");put(749, "kerberos-adm");put(765, "webster");
			put(873, "rsync");put(989, "ftps-data");put(990, "ftps");put(992, "telnets");
			put(993, "imaps");put(994, "ircs");put(995, "pop3s");put(1080, "socks");
			put(1093, "proofd");put(1094, "rootd");put(1194, "openvpn");put(1099, "rmiregistry");
			put(1214, "kazaa");put(1241, "nessus");put(1352, "lotusnote");put(1433, "ms-sql-s");
			put(1434, "ms-sql-m");put(1524, "ingreslock");put(1525, "prospero-np");
			put(1645, "datametrics");put(1646, "sa-msg-port");put(1649, "kermit");put(1701, "l2f");
			put(1812, "radius");put(1813, "radius-acct");put(1863, "msnp");put(1957, "unix-status");
			put(1958, "log-server");put(1959, "remoteping");put(2000, "cisco-sccp");
			put(2010, "search");put(2010, "pipe_server");put(2049, "nfs");put(2086, "gnunet");
			put(2101, "rtcm-sc104");put(2119, "gsigatekeeper");put(2135, "gris");
			put(2401, "cvspserver");put(2430, "venus");put(2431, "venus-se");put(2432, "codasrv");
			put(2433, "codasrv-se");put(2583, "mon");put(2628, "dict");put(2811, "gsiftp");
			put(2947, "gpsd");put(3050, "gds_db");put(3130, "icpv2");put(3306, "mysql");
			put(3493, "nut");put(3632, "distcc");put(3689, "daap");put(3690, "svn");
			put(4031, "suucp");put(4094, "sysrqd");put(4190, "sieve");put(4369, "epmd");
			put(4373, "remctl");put(4569, "iax");put(4691, "mtn");put(4899, "radmin-port");
			put(5002, "rfe");put(5050, "mmcc");put(5060, "sip");put(5061, "sip-tls");
			put(5190, "aol");put(5222, "xmpp-client");put(5269, "xmpp-server");put(5308, "cfengine");
			put(5353, "mdns");put(5432, "postgresql");put(5556, "freeciv");put(5672, "amqp");
			put(5688, "ggz");put(6000, "x11");put(6001, "x11-1");put(6002, "x11-2");
			put(6003, "x11-3");put(6004, "x11-4");put(6005, "x11-5");put(6006, "x11-6");
			put(6007, "x11-7");put(6346, "gnutella-svc");put(6347, "gnutella-rtr");
			put(6444, "sge_qmaster");put(6445, "sge_execd");put(6446, "mysql-proxy");
			put(7000, "afs3-fileserver");put(7001, "afs3-callback");put(7002, "afs3-prserver");
			put(7003, "afs3-vlserver");put(7004, "afs3-kaserver");put(7005, "afs3-volser");
			put(7006, "afs3-errors");put(7007, "afs3-bos");put(7008, "afs3-update");
			put(7009, "afs3-rmtsys");put(7100, "font-service");put(8080, "http-alt");
			put(9101, "bacula-dir");put(9102, "bacula-fd");put(9103, "bacula-sd");
			put(9667, "xmms2");put(10809, "nbd");put(10050, "zabbix-agent");
			put(10051, "zabbix-trapper");put(10080, "amanda");put(11371, "hkp");
		};
	};
	//Signatures from couple of services 	
	private static final String [] Signatures = {"Server: Apache", "FTP" ,  "OpenSSH", 
		"Microsoft-IIS", "Postfix", "MySQL", "Microsoft SQL Server", };
	
	//---main function
	public static void main(String[] args) 
	{
		//--Get the parameters from user input and validate them
		if(args.length < 2)
		{
			Usage();
			System.exit(-1);
		}else if( !args[0].equals("-t") )
		{
			getPorts(args[0]);
			Hostname = args[1];
			System.out.println("[+]Starting TCP scan on host: " +Hostname );
			System.out.println("[+]Scanning ports from: " +PortFrom  + " till: " + PortTill );
			System.out.println("++++++++++++++++++++++++++++++++");
			StartTCPScan(Integer.parseInt(PortFrom), Integer.parseInt(PortTill));
		}
		else if(args[0].equals("-t"))
		{//Start scanning TCP
			myTIMEOUT = Integer.parseInt(args[1]);
			getPorts(args[2]);
			Hostname = args[3];
			System.out.println("[+]Starting TCP scan on host: " +Hostname );
			System.out.println("[+]Scanning ports from: " +PortFrom  + " till: " + PortTill );
			System.out.println("[+]Timeout: " + myTIMEOUT);
			System.out.println("++++++++++++++++++++++++++++++++");
			StartTCPScan(Integer.parseInt(PortFrom), Integer.parseInt(PortTill));			
		}else{
			System.out.println("[!]Error." );
			Usage();
			System.exit(-1);
		}

	}
	//--Print out usage of the application with an example
	private static void Usage()
	{
		System.out.println("\nUsage: java PortScanner [OPTION] [Portrange] Hostname");
		System.out.println("Option:\t-t <Timeout>");
		System.out.println("Port Range: 1-65535");
		System.out.println("Example: java PortScanner -t<timeout time in milisec> 1-1024 127.0.0.1\n");
		System.out.println("Example 2: java PortScanner 1-1024 127.0.0.1\n");
		System.out.println("========= Written by ============");
		System.out.println("=======  SAEED GHIASSY  ========");

	}//-- End of Usage
	
	//---------- StartTCPScan function from given ports
	private static void StartTCPScan(int start, int end)
	{
		System.out.println("[+]Discovering...");		
		for(int i=start; i< end; i++)
		{
			SocketAddress sockaddr = new InetSocketAddress(Hostname, i);
			Socket mySocket = new Socket();
			try {
				mySocket.connect(sockaddr, myTIMEOUT);//timeout for connection is 1 Second
				//timeout in 3 second if cannot read from socket 
				mySocket.setSoTimeout(5000);
				if(mySocket.isConnected())
				{
					//On port 80 Signatures matching wont be tested
					if( i ==80)
					{
						FinalReport += "Port " + i + " is open.\t\t" + getService(i)+ 
								"\t\t\t\n";
					}else{
						//read the 255 from connected socket and send it
						//to GuesssService function to check Signatures
						InputStream istream = mySocket.getInputStream();
						String output = "";
						BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));
						char[] inputChars = new char[255];
						receiveRead.read(inputChars);
						output = new String(inputChars);
						
						FinalReport += "Port " + i + " is open.\t\t" + getService(i)+ 
								"\t\t\t" + GuessService(output) + "\n";						
					}										
				}
				mySocket.close();
			} catch (IOException e) {//conection timeout exceptions 
				if( ( counter % 2 ) == 0)
				{
					System.out.print("[+]Please wait" + "\r");
					counter+=1;
				}else{
					System.out.print("[+]Scanning.. .." + "\r");
					counter+=1;
				}
			}
			
		}
		System.out.println("Port Numbers\t\tStandard Service\t\tGuessed from Signature");
		System.out.println("------------\t\t----------------\t\t----------------------");
		System.out.println(FinalReport);
	}
	//------ Get the port number range from input
	private static void getPorts(String arg)
	{
		if(arg.contains("-"))
		{
			String [] parts = arg.split("-");
			if(Integer.parseInt(parts[0]) <= 0)
			{
				PortFrom = "1";
			}else{
				PortFrom = parts[0];
			}
			if(Integer.parseInt(parts[1]) > 65535)
			{
				PortTill = "65535";
			}else{
				PortTill = parts[1];
			}
			
		}else{
			throw new IllegalArgumentException("Bad port input format!");
		}
	}//--- end of getPorts function

	/* Default services are determined according to file 
	*  /etc/services in Linux
	*  
	*/
	private static String getService(int port)
	{
		 Iterator it = MyServices.entrySet().iterator();
		 while (it.hasNext()) {
			 
			 Map.Entry pairs = (Map.Entry)it.next();
		     if(Integer.parseInt(pairs.getKey().toString()) == port)
		     {
		    	 return pairs.getValue().toString();
		     }
		    }				
		return "Unknown";
	}
	//Signatures scanning using pattern matching in java
	private static String GuessService(String input)
	{
		for(int i=0; i < Signatures.length; i++)
		{
			Pattern myPattern = Pattern.compile(Signatures[i]);
			Matcher myMatcher = myPattern.matcher(input);
			if(myMatcher.find())
			{
				return Signatures[i];
			}
		}
		return "Unknown";
	}//end of GuessServices function
}//--End of Application
