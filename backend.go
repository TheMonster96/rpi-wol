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


	"golang.org/x/crypto/ssh"
)

var(
	home_path = "/home/francesco/.ssh/"
)

func loadAuthorizedKeys() (map[string]bool, error){

	authorizedKeysBytes, err := os.ReadFile(home_path + "authorized_keys")

	if err!= nil {
		return nil, err
	}

	authorizedKeysMap := make(map[string]bool)

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		
		if err != nil {
			return nil, err		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	return authorizedKeysMap, nil
}
//TODO: Change this to an SSH Request instead of an HTTP Request
/*func recvMACAddress(w http.ResponseWriter, req *http.Request){
	_ = w
		
	query := req.URL.Query()

	fmt.Printf("received MAC Address: %s", query.Get("MACAddress"))

	macAddress, err := net.ParseMAC(query.Get("MACAddress"))
	
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


}*/

func main(){

	authorizedKeysMap, err:= loadAuthorizedKeys()

	if err != nil{
		log.Fatal("Error: ", err)
	}

	sshConfig := &ssh.ServerConfig{
		
		PublicKeyCallback: func(c ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubkey.Marshal())] {
				return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubkey),
				},
			}, nil
		} 
		return nil, fmt.Errorf("Unknown public key for %q", c.User())
		},
	}

	privateBytes, err := os.ReadFile(home_path + "id_ed25519")

	if err != nil {
		log.Fatal("Couldn't read/find private key:  \n use 'ssh-keygen -t rsa' to generate a key pair", err)
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	
	if err != nil {
		log.Fatal("Couldn't parse private key: ", err)
	}

	sshConfig.AddHostKey(privateKey)

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

		sshConn, chans, reqs, err:= ssh.NewServerConn(conn, sshConfig)
		if err != nil {
			fmt.Printf("Error while handshaking: %s\n", err)
			continue
		}

		fmt.Printf("New connection request received from: %s at %v \n", conn.RemoteAddr(), time.Now())
		fmt.Printf("Logged in with key %s\n", sshConn.Permissions.Extensions["pubkey-fp"])

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
		
				//defer channel.Close()
			
				for{
				/*n, err:= channel.Read(buf)
				if err != nil{
					fmt.Printf("Error while reading, closing channel connection")
					if error :=channel.Close(); error != nil{
						fmt.Printf("Error while closing channel connection breh")
					}
					return
				}*/

				//fmt.Print("Received bytes and length: %s, %d \n", string(buf[:n]), n)
				
				response := fmt.Sprintf("Buongiorno\n")
				channel.Write([]byte(response))
				channel.Close()	
				}
			}()


		}
		//buf:= make([]byte, 1024)
		
	}
}
