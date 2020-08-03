#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *	
import requests
import socket
import os
import sys
import json
import time
import re
import urllib.parse

class Information_gathering():
	def __init__(self):
		self.menu = '''\n\n
		    {1}  -- Whois Lookup
		    {2}  -- Traceroute
		    {3}  -- DNS Lookup
		    {4}  -- Reverse DNS Lookup
		    {5}  -- Banner Grabbing & GeoIP Lookup 
		    {6}  -- Reverse IP Lookup
		    {7}  -- Port Scan
		    {8}  -- DNS Host Records (Subdomains)
		    {9}  -- Hidden Directories
		    {10} -- Extract Links
		    {11} -- Shared DNS Servers Info
		    {12} -- DNS (A) Record Info
		    {13} -- DNS Zone Tranfer Info
		    {14} -- Autonomous System Lookup (AS / ASN / IP)
		    {15} -- Subnet Lookup (CIDR)
		    {99} -- Exit
		 '''
		self.headers = {
		    'Accept-Encoding': 'gzip, deflate, sdch',
		    'Accept-Language': 'en-US,en;q=0.8',
		    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
		    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		    'Referer': 'http://www.wikipedia.org/',
		    'Connection': 'keep-alive',
			}
		self.target_links = []

	def clear_screen(self):
		if 'nt' in os.name:
			os.system('cls')
		else:
			os.system('clear')

	def quit(self):
	    con = input('\nContinue [Y/n] -> ')
	    if con.upper() == 'N':
	    	sys.exit()
	    else:
	    	self.clear_screen()
	    	print(self.menu)
	    	self.select()

	def whois(self):
		try:
			print('\n[ ==> ] Available Domains : .NET, .EDU, .COM\n')
			target = input('Enter Your Target Domain : ')	# Nameservers can also be acceptable like ns1.google.com etc
			url = 'https://api.hackertarget.com/whois/?q=' + target
			print('\n[###] WHOis Information For : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()
		
	def trace_route(self):
		try:
			target = input('\nEnter Your Target : ')
			url = 'https://api.hackertarget.com/mtr/?q=' + target
			print('\n')
			print('[###] Tracerouting : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def dns_lookup(self):
		try:
			target = input('\nEnter Your Target : ')
			url = 'https://api.hackertarget.com/dnslookup/?q=' + target
			print('\n')
			print('[###] DNS Lookup Info. For  : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def reverse_dns_lookup(self):
		try:
			target = input('\nEnter Your Target (IP) : ')
			url = 'https://api.hackertarget.com/reversedns/?q=' + target
			print('\n')
			print('[###] Reverse DNS Record For An IP Address  : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def geoIP_lookup(self):
		try:
			print('\nNote: Nameservers can also be acceptable like "ns1.google.com" etc\n')
			target = input('Enter Your Target Domain : ')
			response = requests.get('https://' + target, headers=self.headers)
			print('\n[~#~ Banner Grabbing ' + target)
			print('\n' + str(response.headers))

			ip = socket.gethostbyname(target)
			print('\nThe IP address of ' + target + ' is: ' + ip + '\n')
			print('\nIP Information:\n')
			response = requests.get('http://ip-api.com/json/' + ip, headers=self.headers)
			data = json.loads(response.text)

			print(' IP \t\t\t:\t ' + data['query'])
			print(' Status \t\t:\t ' + data['status'])
			print(' Continent Code \t:\t ' + data['countryCode'])
			print(' Country        \t:\t ' + data['country'])
			print(' Country Code \t\t:\t ' + data['countryCode'])
			print(' Region \t\t:\t ' + data['region'])
			print(' Region Name \t\t:\t ' + data['regionName'])
			print(' City \t\t\t:\t ' + data['city'])
			print(' Postal / Zip \t\t:\t ' + data['zip'])
			print(' Latitude \t\t:\t ' + str(data['lat']))
			print(' Longitude \t\t:\t ' + str(data['lon']))
			print(' Time Zone \t\t:\t ' + data['timezone'])
			print(' ISP \t\t\t:\t ' + data['isp'])
			print(' Organization \t\t:\t ' + data['org'])
			print(' as \t\t\t:\t ' + data['as'] + '\n')
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def reverse_ip_lookup(self):
		try:
			target = input('Enter Your Target Domain : ')
			host = socket.gethostbyname(target)
			domain = socket.gethostbyaddr(host)

			print('\n\nIP Address : ' + host)
			print('Domain Name: ' + domain[0] + '\n')
		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def scan(self):
		target = input('\nEnter Your Target : ')
		ip  = socket.gethostbyname(target)
		start_port = int(input('Enter Starting Port : '))
		end_port = int(input('Enter Ending Port : '))

		print('\n[ --> ] Scanning ' + ip + ' For Open TCP Ports ...\n')
		print('[***] Scanning Started At : ' + str(round(time.time()),3))
		print('\n')
		if start_port == end_port:
			end_port += 1

		for x in range(start_port, end_port):
			packet = IP(dst=ip)/TCP(dport=x, flags='S')
			response = sr1(packet, timeout=0.5, verbose=0)

			if(str(type(response))=="<type 'NoneType'>"):
				pass

			elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
				print(' > Port ' + str(x) + ' is Open!')
			sr1(IP(dst=ip)/TCP(dport=x, flags='R'), timeout=0.5, verbose=0)
			end_time = time.time()

		print('\n[~#~ Scan is Complete ...!\n')
		print('[***] Scanning Completed In : ' + str(round(end_time - time.time()),3) + '\n')

	def subdomains(self):
		try:
			target = input('Enter Your Target Domain : ')
			print('\n[#***#] Finding Subdomains For ' + target + '\n')
			with open('subdomains.txt', 'r') as word_list:
				for word in word_list:
				    word = word.strip()		# removes extra white spaces
				    domain = word + "." + target
				    try:
				    	response = requests.get('https://' + domain, headers=self.headers)
				    	if response:	# if return something
				    	    print('[+] Discovered subdomains --> ' + domain)
				    except requests.exceptions.ConnectionError:
				    		pass
		except KeyboardInterrupt:
			print('\n[*] Closing ...\n')
			self.quit()

	def hidden_dir(self):
		try:
			target = input('Enter Your Target Domain : ')
			print('\n[#***#] Finding Hidden Paths For ' + target + '\n')
			with open('commons.txt', 'r') as word_list:
				for word in word_list:
				    word = word.strip()		# removes extra white spaces
				    domain = target + '/' + word
				    try:
				        response = requests.get('http://' + domain, headers=self.headers)	# function call
				        if response:
				        	print('[+] Discovered URLs/Path --> ' + domain)
				    except requests.exceptions.ConnectionError:
				    	pass
		except KeyboardInterrupt:
			print('\n[*] Closing ...\n')
			self.quit()

	def crawl(self, url):
		try:
			response = requests.get(url, headers=self.headers)
			href_links = re.findall('(?:href=")(.*?)"', response.content)
			for link in href_links:
				link = urllib.parse.urljoin(url, link)
				if '#' in link:
					link = link.split('#')[0]

				if url in link and link not in self.target_links:
					self.target_links.append(link)
					print(link)
					crawl(link)

		except requests.exceptions.ConnectionError:
			pass

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def extract_links(self):
		try:
			target = input('Enter Your Target Domain With http(s) : ')
			print('\n[#***#] Extracting Links From < ' + target + ' >\n')
			self.crawl(target)

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def shared_dns_info(self):
		try:
			print('\nNote: Nameservers can also be acceptable like "ns1.google.com" etc\n')
			target = input('Enter Your Target Domain : ')
			url = 'https://api.hackertarget.com/findshareddns/?q=' + target
			print('\n')
			print('[###] Hosts Sharing DNS Servers for : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
			print('\n')

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def dns_a_record(self):
		try:
			target = input('Enter Your Target : ')
			url = 'https://api.hackertarget.com/hostsearch/?q=' + target
			print('\n')
			print('[###] Forward DNS (A) Records For A Domain  : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)
			print('\n')

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def dns_zonetransfer(self):
		try:
			target = input('Enter Your Target Domain : ')
			url = 'https://api.hackertarget.com/zonetransfer/?q=' + target
			print('\n')
			print('[###] Zone Transfere Informatin For A Target Domain : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def autonomous_system_lookup(self):
		try:
			target = input('Enter Your Target Domain : ')
			ip = socket.gethostbyname(target)
			url = 'https://api.hackertarget.com/aslookup/?q=' + str(ip)
			print('\n')
			print('[###] Autonomous System Lookup For A Target Domain : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()

	def subnet_lookup(self):
		try:
			target = input('Enter Your Target Subnet : ')
			url = 'https://api.hackertarget.com/subnetcalc/?q=' + target
			print('\n')
			print('[###] Processing Subnet Lookup For A Target Domain : ' + target + '\n')
			response = requests.get(url, headers=self.headers)
			print(response.text)

		except KeyboardInterrupt:
			print('\n[~] Exitting ...\n')
			self.quit()


	def select(self):
		try:
			choice = int(input("\nroot~# "))
			if choice == 1:
				self.clear_screen()			
				
				print('\n')
				print("""
				 .-.  .-..-. .-. .---.  ,-.   .---. 
				| |/\| || | | |/ .-. ) |(|  ( .-._)
				| /  \ || `-' || | |(_)(_) (_) \   
				|  /\  || .-. || | | | | | _  \ \  
				|(/  \ || | |)|\ `-' / | |( `-'  ) 
				(_)   \|/(  (_) )---'  `-' `----'  
				       (__)    (_)                 
				                                                                                  
				""")
				self.whois()		# function call
				self.quit()

			elif choice == 2:
				self.clear_screen()

				print('\n')
				print("""
				 ____ ____   __   ___ ____ ____ _____ __  __ ____ ____ 
				(_  _(  _ \ /__\ / __( ___(  _ (  _  (  )(  (_  _( ___)
				  )(  )   //(__)( (__ )__) )   /)(_)( )(__)(  )(  )__) 
				 (__)(_)\_(__)(__\___(____(_)\_(_____(______)(__)(____)
				""")
				self.trace_route()		#function call
				self.quit()	
			
			elif choice == 3:
				self.clear_screen()

				print('\n')
				print("""
				    .S_sSSs     .S_sSSs      sSSs        S.        sSSs_sSSs      sSSs_sSSs     .S    S.    .S_sSSs    
				.SS~YS%%b   .SS~YS%%b    d%%SP        SS.      d%%SP~YS%%b    d%%SP~YS%%b   .SS    SS.  .SS~YS%%b   
				S%S   `S%b  S%S   `S%b  d%S'          S%S     d%S'     `S%b  d%S'     `S%b  S%S    S&S  S%S   `S%b  
				S%S    S%S  S%S    S%S  S%|           S%S     S%S       S%S  S%S       S%S  S%S    d*S  S%S    S%S  
				S%S    S&S  S%S    S&S  S&S           S&S     S&S       S&S  S&S       S&S  S&S   .S*S  S%S    d*S  
				S&S    S&S  S&S    S&S  Y&Ss          S&S     S&S       S&S  S&S       S&S  S&S_sdSSS   S&S   .S*S  
				S&S    S&S  S&S    S&S  `S&&S         S&S     S&S       S&S  S&S       S&S  S&S~YSSY%b  S&S_sdSSS   
				S&S    S&S  S&S    S&S    `S*S        S&S     S&S       S&S  S&S       S&S  S&S    `S%  S&S~YSSY    
				S*S    d*S  S*S    S*S     l*S        S*b     S*b       d*S  S*b       d*S  S*S     S%  S*S         
				S*S   .S*S  S*S    S*S    .S*P        S*S.    S*S.     .S*S  S*S.     .S*S  S*S     S&  S*S         
				S*S_sdSSS   S*S    S*S  sSS*S          SSSbs   SSSbs_sdSSS    SSSbs_sdSSS   S*S     S&  S*S         
				SSS~YSSY    S*S    SSS  YSS'            YSSP    YSSP~YSSY      YSSP~YSSY    S*S     SS  S*S         
				            SP                                                              SP          SP          
				            Y                                                               Y           Y           
				                                                                                                    
				""")
				self.dns_lookup()		#function call
				self.quit()	

			elif choice == 4:
				self.clear_screen()			
				
				print('\n')
				print("""
				 ,-.                            ,-.  .  .  ,-.  
				|  )                           |  \ |\ | (   ` 
				|-<  ,-. . , ,-. ;-. ,-. ,-.   |  | | \|  `-.  
				|  \ |-' |/  |-' |   `-. |-'   |  / |  | .   ) 
				'  ' `-' '   `-' '   `-' `-'   `-'  '  '  `-'  
				                                                                                       
				""")
				self.reverse_dns_lookup()		# function call
				self.quit()	

			elif choice == 5:
				self.clear_screen()			
				
				print('\n')
				print("""
				,---.          ,-_/ .-,--.    ,           .           
				|  -'  ,-. ,-. '  |  '|__/    )   ,-. ,-. | , . . ,-. 
				|  ,-' |-' | | .^ |  ,|      /    | | | | |<  | | | | 
				`---|  `-' `-' `--'  `'      `--' `-' `-' ' ` `-^ |-' 
				 ,-.|                                             |   
				 `-+'                                             '                                                               
				                                                                                       
				""")
				self.geoIP_lookup()		# function call
				self.quit()

			elif choice == 6:
				self.clear_screen()			
				
				print('\n')
				print("""
			  _____                                _____ _____    _                 _                
			 |  __ \                              |_   _|  __ \  | |               | |               
			 | |__) |_____   _____ _ __ ___  ___    | | | |__) | | |     ___   ___ | | ___   _ _ __  
			 |  _  // _ \ \ / / _ \ '__/ __|/ _ \   | | |  ___/  | |    / _ \ / _ \| |/ / | | | '_ \ 
			 | | \ \  __/\ V /  __/ |  \__ \  __/  _| |_| |      | |___| (_) | (_) |   <| |_| | |_) |
			 |_|  \_\___| \_/ \___|_|  |___/\___| |_____|_|      |______\___/ \___/|_|\_\\__,_| .__/ 
			                                                                                  | |    
			                                                                                  |_|                          
													                                                                                  
													""")
				self.reverse_ip_lookup()	# function call
				self.quit()

			elif choice == 7:
				self.clear_screen()			
				
				print('\n')
				print("""

			 ___   ___    __    ____  _  _    ___   ___    __    _  _ 
			/ __) / __)  /__\  (  _ \( \/ )  / __) / __)  /__\  ( \( )
			\__ \( (__  /(__)\  )___/ \  /   \__ \( (__  /(__)\  )  ( 
			(___/ \___)(__)(__)(__)   (__)   (___/ \___)(__)(__)(_)\_)                

			      """)
				self.scan()		# function call
				self.quit()

			elif choice == 8:
				self.clear_screen()			
				
				print('\n')
				print("""
			.d88b.       8       8                      w            
			YPwww. 8   8 88b. .d88 .d8b. 8d8b.d8b. .d88 w 8d8b. d88b 
			    d8 8b d8 8  8 8  8 8' .8 8P Y8P Y8 8  8 8 8P Y8 `Yb. 
			`Y88P' `Y8P8 88P' `Y88 `Y8P' 8   8   8 `Y88 8 8   8 Y88P 
	                                                         
				""")
				self.subdomains()		# function call
				self.quit()

			elif choice == 9:
				self.clear_screen()			
				
				print('\n')
				print("""
		                __   __   ___          __       ___       __  
			|__| | |  \ |  \ |__  |\ |    |__)  /\   |  |__| /__` 
			|  | | |__/ |__/ |___ | \|    |    /~~\  |  |  | .__/ 
	                                                                               
				""")
				self.hidden_dir()		# function call
				self.quit()

			elif choice == 10:
				self.clear_screen()			
				
				print('\n')
				print("""
			  _______       __                   __       ___    __       __          
			 |   _   .--.--|  |_.----.---.-.----|  |_    |   |  |__.-----|  |--.-----.
			 |.  1___|_   _|   _|   _|  _  |  __|   _|   |.  |  |  |     |    <|__ --|
			 |.  __)_|__.__|____|__| |___._|____|____|   |.  |__|__|__|__|__|__|_____|
			 |:  1   |                                   |:  1   |                    
			 |::.. . |                                   |::.. . |                    
			 `-------'                                   `-------'                    
	                                                                              
				""")
				self.extract_links()		# function call
				self.quit()

			elif choice == 11:
				self.clear_screen()			
				
				print('\n')
				print("""
			,d88~~\ 888                                       888       888~-_   888b    | ,d88~~\ 
			8888    888-~88e   /~~~8e  888-~\  e88~~8e   e88~\888       888   \  |Y88b   | 8888    
			`Y88b   888  888       88b 888    d888  88b d888  888       888    | | Y88b  | `Y88b   
			 `Y88b, 888  888  e88~-888 888    8888__888 8888  888       888    | |  Y88b |  `Y88b, 
			   8888 888  888 C888  888 888    Y888    , Y888  888       888   /  |   Y88b|    8888 
			\__88P' 888  888  "88_-888 888     "88___/   "88_/888       888_-~   |    Y888 \__88P' 
			                                                                                       
	           """)
				self.shared_dns_info()		# function call
				self.quit()

			elif choice == 12:
				self.clear_screen()			
				
				print('\n')
				print("""
			  *******   ****     **  ********       *******                                        **
			/**////** /**/**   /** **//////       /**////**                                      /**
			/**    /**/**//**  /**/**             /**   /**   *****   *****   ******  ******     /**
			/**    /**/** //** /**/*********      /*******   **///** **///** **////**//**//*  ******
			/**    /**/**  //**/**////////**      /**///**  /*******/**  // /**   /** /** /  **///**
			/**    ** /**   //****       /**      /**  //** /**//// /**   **/**   /** /**   /**  /**
			/*******  /**    //*** ********       /**   //**//******//***** //****** /***   //******
			///////   //      /// ////////        //     //  //////  /////   //////  ///     ////// 
			                                                                                                    
			""")
				self.dns_a_record()		# function call
				self.quit()

			elif choice == 13:
				self.clear_screen()			
				
				print('\n')
				print("""
			 _____   .---.  .-. .-.,---.    _______ ,---.    .--.  .-. .-.   .---. ,---.,---.  ,---.    
			/___  / / .-. ) |  \| || .-'   |__   __|| .-.\  / /\ \ |  \| |  ( .-._)| .-'| .-'  | .-.\   
			   / /) | | |(_)|   | || `-.     )| |   | `-'/ / /__\ \|   | | (_) \   | `-.| `-.  | `-'/   
			  / /(_)| | | | | |\  || .-'    (_) |   |   (  |  __  || |\  | _  \ \  | .-'| .-'  |   (    
			 / /___ \ `-' / | | |)||  `--.    | |   | |\ \ | |  |)|| | |)|( `-'  ) | |  |  `--.| |\ \   
			(_____/  )---'  /(  (_)/( __.'    `-'   |_| \)\|_|  (_)/(  (_) `----'  )\|  /( __.'|_| \)\  
			        (_)    (__)   (__)                  (__)      (__)            (__) (__)        (__) 
			                                                                                       
			                                                                                       
			""")
				self.dns_zonetransfer()		# function call
				self.quit()

			elif choice == 14:
				self.clear_screen()			
					
				print('\n')
				print("""
				                                                                                       
			    :::      ::::::::  ::::    :::            :::          :::      ::::::::             :::      ::::::::::: :::::::::  
			  :+: :+:   :+:    :+: :+:+:   :+:           :+:         :+: :+:   :+:    :+:           :+:           :+:     :+:    :+: 
			 +:+   +:+  +:+        :+:+:+  +:+          +:+         +:+   +:+  +:+                 +:+            +:+     +:+    +:+ 
			+#++:++#++: +#++:++#++ +#+ +:+ +#+         +#+         +#++:++#++: +#++:++#++         +#+             +#+     +#++:++#+  
			+#+     +#+        +#+ +#+  +#+#+#        +#+          +#+     +#+        +#+        +#+              +#+     +#+        
			#+#     #+# #+#    #+# #+#   #+#+#       #+#           #+#     #+# #+#    #+#       #+#               #+#     #+#        
			###     ###  ########  ###    ####      ###            ###     ###  ########       ###            ########### ###                                                                                         
				""")
				self.autonomous_system_lookup()		# function call
				self.quit()

			elif choice == 15:
				self.clear_screen()			
					
				print('\n')
				print("""
				 .d8888b.           888                        888         888                       888                        
				d88P  Y88b          888                        888         888                       888                        
				Y88b.               888                        888         888                       888                        
				 "Y888b.   888  888 88888b.  88888b.   .d88b.  888888      888      .d88b.   .d88b.  888  888 888  888 88888b.  
				    "Y88b. 888  888 888 "88b 888 "88b d8P  Y8b 888         888     d88""88b d88""88b 888 .88P 888  888 888 "88b 
				      "888 888  888 888  888 888  888 88888888 888         888     888  888 888  888 888888K  888  888 888  888 
				Y88b  d88P Y88b 888 888 d88P 888  888 Y8b.     Y88b.       888     Y88..88P Y88..88P 888 "88b Y88b 888 888 d88P 
				 "Y8888P"   "Y88888 88888P"  888  888  "Y8888   "Y888      88888888 "Y88P"   "Y88P"  888  888  "Y88888 88888P"  
				                                                                                                       888      
				                                                                                                       888                                                                                               
				                                                                                       
				""")
				self.subnet_lookup()		# function call
				self.quit()


			elif choice == 99:
				sys.exit()

		except KeyboardInterrupt:
			print('\n[!] Exitting ...\n')

		self.quit()

	def run(self):
		self.clear_screen()
		print(self.menu)
		self.select()


if __name__ == '__main__':

		reconnaisance = Information_gathering()
		reconnaisance.run()