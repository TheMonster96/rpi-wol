package main

/*
	TODO:
	-- Make an sshServer struct which contains:
		listener,
		context,
		sshConfig,
		AuthorizedKeysMap,
		...
	-- Switch to a YAML file which contains: 
		Authorized key
		User name
		MAC address
		...
*/

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
	home_path = "/home/francesco/.ssh/"
)

type SSHUser struct{
	Username string `yaml:"username"`
	PubKey string `yaml:"pubkey"`
	MACAddress string `yaml:"mac_address"`
}

type SSHUsers struct {
	Users []SSHUser `yaml:"sshusers"`
}

type SSHServer struct{

	AuthorizedUsers SSHUsers 
	Config *ssh.ServerConfig
	TCPListener net.Listener
	PrivateKey ssh.Signer

}

func sendWoL(MACAddress string){

	fmt.Printf("received MAC Address: %s", MACAddress)

	macAddress, err := net.ParseMAC(MACAddress)
	
	if err != nil{
		log.Fatal(err)	
	}

	fmt.Printf("\n%s", macAddress.String())

	packet:= make([]byte, 102)

	for i:=0; i<6; i++ {
		packet[i]= 0xFF
	}

	for i:=0; i<16; i++ {
		copy(packet[6+i*6:], macAddress)	
	}

	fmt.Printf(string(packet))
	
	conn, err := net.Dial("udp", "255.255.255.255:9")
	
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	udpConn := conn.(*net.UDPConn)
	udpConn.SetWriteBuffer(len(packet))

	_, err = udpConn.Write(packet)

	if err != nil {
		log.Fatal(err)
	}


}


func loadYAMLAuthorizedKeys(server *SSHServer) (error){

	authorizedUsers, err := os.ReadFile(home_path + "authorized_keys.yaml")
	var users SSHUsers
	
	if err!= nil {
		return err
	}

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
		return nil, fmt.Errorf("Unknown public key for %q", c.User())
		},
	}

}

func addPrivateKey(server *SSHServer, PrivKeyPath string) (error) {

	privateBytes, err := os.ReadFile(PrivKeyPath)

	if err != nil {
		log.Fatal("Couldn't read/find private key:  \n use 'ssh-keygen -t rsa' to generate a key pair", err)
		return err
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	
	if err != nil {
		//log.Fatal("Couldn't parse private key: ", err)
		return err
	}
	
	server.Config.AddHostKey(privateKey)
	return nil
}


func main(){
	sshServer := SSHServer{}
	
	err:= loadYAMLAuthorizedKeys(&sshServer)

	if err != nil{
		log.Fatal("Error: ", err)
	}
	
	initSSHConfig(&sshServer, sshServer.AuthorizedUsers)
	
	addPrivateKey(&sshServer, home_path + "id_ed25519")

	listener, err := net.Listen("tcp", "0.0.0.0:2222")

	if err != nil {
		log.Fatal("Failed to open TCP listener: ", err)  
	}

	fmt.Printf("Listening on 0.0.0.0:2222\n")

	defer listener.Close()

	for {
		conn, err:= listener.Accept()

		if err != nil {
			fmt.Printf("Error while accepting incoming connection: %s", err)
			continue
		}

		sshConn, chans, reqs, err:= ssh.NewServerConn(conn, sshServer.Config)
		if err != nil {
			fmt.Printf("Error while handshaking: %s\n", err)
			continue
		}

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
				log.Fatal("Could not accept channel, %v\n", err)
			}
			go func(){
		
							
				response := fmt.Sprintf("Buongiorno\n")
				channel.Write([]byte(response))
				//sendWoL("58-47-Ca-70-58-93")
				channel.Close()	
				
			}()


		}
		
	}
}
