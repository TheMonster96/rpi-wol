package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"time" 
	"bytes"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var(
	log_path =  "/opt/rpi-wol/log.txt"
	home_path = "/opt/rpi-wol/.ssh/"
)

/*===================== LOGGING FUNCTIONALITY ======================*/

func initLogger(server *SSHServer) error {
	
	logFile, err := os.OpenFile(log_path, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)

	if err != nil {
		return err
	}

	server.LogFile = log.New(logFile, "RPI-WOL", log.LstdFlags | log.Lshortfile)

	return nil
}

func logError(logFile *log.Logger, errorString string) {
	logFile.Println("[ERROR] at %s : %s ", time.Now(), errorString);
}

func logInfo(logFile *log.Logger, infoString string) {
	logFile.Println("[INFO] at %s : %s ", time.Now(), infoString);
}


type SSHServer struct{

	LogFile *log.Logger
	AuthorizedUsers SSHUsers 
	Config *ssh.ServerConfig
	TCPListener net.Listener
	PrivateKey ssh.Signer

}

type SSHUser struct{
	Username string `yaml:"username"`
	PubKey string `yaml:"pubkey"`
	MACAddress string `yaml:"mac_address"`
}

type SSHUsers struct {
	Users []SSHUser `yaml:"sshusers"`
}



func sendWoL(MACAddress string, logFile *log.Logger){

	//logInfo(logFile, fmt.Sprintf("Received MAC Address : %s", MACAddress))

	macAddress, err := net.ParseMAC(MACAddress)
	
	if err != nil{
		logError(logFile, err.Error())	
	}

	packet:= make([]byte, 102)

	for i:=0; i<6; i++ {
		packet[i]= 0xFF
	}

	for i:=0; i<16; i++ {
		copy(packet[6+i*6:], macAddress)	
	}
	
	conn, err := net.Dial("udp", "255.255.255.255:9")
	
	if err != nil {
		logError(logFile, err.Error())
	}

	defer conn.Close()

	udpConn := conn.(*net.UDPConn)
	udpConn.SetWriteBuffer(len(packet))

	_, err = udpConn.Write(packet)

	if err != nil {
		logError(logFile, err.Error())
	}
}

func loadYAMLAuthorizedKeys(server *SSHServer) (error){

	authorizedUsers, err := os.ReadFile(home_path + "authorized_keys.yaml")
	var users SSHUsers
	
	//Error reading the authorized_keys.yaml file 
	if err!= nil {
		logError(server.LogFile, err.Error()) 
		return err
	}

	//Error parsing the authorized_keys.yaml content 
	if err := yaml.Unmarshal(authorizedUsers, &users); err != nil {
		return err
	}

	server.AuthorizedUsers = users

	return nil
}

func initSSHConfig(server *SSHServer, authorizedUsers SSHUsers) {

	server.Config = &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
			for _, sshUser := range authorizedUsers.Users {
				parsedKey, _, _, _, err:= ssh.ParseAuthorizedKey([]byte(sshUser.PubKey))
				if err != nil {
					//Will have to switch to logError(...) to log the parsing error
					fmt.Errorf("Error parsing key for %s, %q", sshUser.Username, err)
				}

				if bytes.Equal(parsedKey.Marshal(), pubkey.Marshal()){
					return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubkey),
						"username": sshUser.Username,
						"macaddress": sshUser.MACAddress,
					},
				}, nil
			} 
		}
		//Will have to switch to logError(...) to log unkown public key error
		return nil, fmt.Errorf("Unknown public key for %q", c.User())
		},
	}

}

func addPrivateKey(server *SSHServer, PrivKeyPath string) (error) {

	privateBytes, err := os.ReadFile(PrivKeyPath)

	if err != nil {
		//Will have to switch to logError(...)  
		log.Fatal("Couldn't read/find private key:  \n use 'ssh-keygen -t rsa' to generate a key pair", err)
		return err
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	
	if err != nil {
		//Will have to switch to logError(...)
		log.Fatal("Couldn't parse private key: ", err)
		return err
	}
	
	server.Config.AddHostKey(privateKey)
	return nil
}


func main(){
	sshServer := SSHServer{}

	err := initLogger(&sshServer)
	
	if err != nil {
		log.Fatal("Logger Init Error: ", err)
	}
	
	sshServer.LogFile.Println("Logger started successfully")

	err = loadYAMLAuthorizedKeys(&sshServer)

	if err != nil{
		//Will have to remove this since it's going directly to the log file, but will have to add exit(1)
		log.Fatal("Authorized Keys Error: ", err)
	}
	
	initSSHConfig(&sshServer, sshServer.AuthorizedUsers)
	
	addPrivateKey(&sshServer, home_path + "id_rsa")

	listener, err := net.Listen("tcp", "0.0.0.0:17035")

	if err != nil {
		//Will have to remove this and pass it to the log file, but will have to add exit(1)
		log.Fatal("Failed to open TCP listener: ", err)  
	}
	
	//Going to the log file directly with logInfo(...)
	fmt.Printf("Listening on 0.0.0.0:17035\n")

	defer listener.Close()

	for {
		conn, err:= listener.Accept()

		if err != nil {
			//Will go directly to log file
			fmt.Printf("Error while accepting incoming connection: %s", err)
			continue
		}

		sshConn, chans, reqs, err:= ssh.NewServerConn(conn, sshServer.Config)
		if err != nil {
			//Will go directly to log file
			fmt.Printf("Error while handshaking: %s\n", err)
			continue
		}

		//Both of these will go to to log file
		fmt.Printf("New connection request received from: %s at %v \n", conn.RemoteAddr(), time.Now())
		fmt.Printf("Logged in with key %s, name: %s, MAC Address: %s \n", sshConn.Permissions.Extensions["pubkey-fp"],sshConn.Permissions.Extensions["username"],sshConn.Permissions.Extensions["macaddress"]  )

		go ssh.DiscardRequests(reqs)

		for newChannel:= range chans{
			
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "Type of channel is unknown")
				continue
			}
			channel, _ , err := newChannel.Accept()
			if err != nil {
				//Will go to log file, but will have to just close the connection instead of exiting the application
				log.Fatal("Could not accept channel, %v\n", err)
			}
			go func(){
				sendWoL(sshConn.Permissions.Extensions["macaddress"], sshServer.LogFile)
				channel.Close()	
			}()
		}
	}
}
