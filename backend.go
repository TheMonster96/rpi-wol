package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/url"
)

func recvMACAddress(w http.ResponseWriter, req *http.Request){
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


}

func main(){

	http.HandleFunc("/recvMACAddress", recvMACAddress)

	fmt.Printf("Starting http server")
	log.Fatal(http.ListenAndServe(":8080", nil))
	//fmt.Printf("ciao")

	}
