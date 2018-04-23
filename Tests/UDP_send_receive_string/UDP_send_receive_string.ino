#include <WiFiUdp.h>
#include <ESP8266WiFi.h>

//#define UDP_TX_PACKET_MAX_SIZE 5 //increase UDP size
 
const char* ssid = "DESKTOP-066IE8G 4066";
const char* password = "janko888";


unsigned int localPort = 8888;      // local port to listen on
IPAddress ip_pc(192, 168, 137, 1);

// buffers for receiving and sending data
char packetBuffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet,
char  ReplyBuffer[] = "acknowledged";       // a string to send back

// An EthernetUDP instance to let us send and receive packets over UDP

WiFiUDP udp;

void setup() {
  Serial.begin(9600);
  delay(10);
  
  WiFi.begin(ssid, password);
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.println("WiFi connected");
  
  udp.begin(localPort);
  Serial.println("UDP listen");
}

void loop() {
  // if there's data available, read a packet
  Serial.println("Zaciatok cakania");
  delay(10000);
  Serial.println("Koniec cakania");
  
  //int packetSize = udp.parsePacket();
  while (1)
  {
    int packetSize = udp.parsePacket();
    if (packetSize)
    {
      Serial.print("Received packet of size ");
      Serial.println(packetSize);
      Serial.print("From ");
      IPAddress remote = udp.remoteIP();
      for (int i = 0; i < 4; i++)
      {
        Serial.print(remote[i], DEC);
        if (i < 3)
        {
          Serial.print(".");
        }
      }
      Serial.print(", port ");
      Serial.println(udp.remotePort());
  
      // read the packet into packetBufffer
      udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
      Serial.println("Contents:");
      for (int i = 0; i < packetSize; i++)
        Serial.print(packetBuffer[i]);
      Serial.println("");
  
      // send a reply, to the IP address and port that sent us the packet we received
      udp.beginPacket(udp.remoteIP(), udp.remotePort());
      udp.write(ReplyBuffer);
      udp.endPacket();
      /*Serial.println("step_1");
      if (udp.beginPacket(ip_pc, 12345))
        Serial.println("step_1_succ");
      else
        Serial.println("step_1_err");
        
      Serial.println("step_2");
      int pom = udp.print(ReplyBuffer);
      Serial.print(pom);
      Serial.println("znakov");
      
      Serial.println("step_3");
      
      if (udp.endPacket())
        Serial.println("step_3_succ");
      else
        Serial.println("step_3_err");
        
      Serial.println("packet sent");
      
      delay(1000);*/
    }
    else
      break;
  }
  delay(10);
}


/*
  Processing sketch to run with this example
 =====================================================

 // Processing UDP example to send and receive string data from Arduino
 // press any key to send the "Hello Arduino" message


 import hypermedia.net.*;

 UDP udp;  // define the UDP object


 void setup() {
 udp = new UDP( this, 6000 );  // create a new datagram connection on port 6000
 //udp.log( true ); 		// <-- printout the connection activity
 udp.listen( true );           // and wait for incoming message
 }

 void draw()
 {
 }

 void keyPressed() {
 String ip       = "192.168.1.177";	// the remote IP address
 int port        = 8888;		// the destination port

 udp.send("Hello World", ip, port );   // the message to send

 }

 void receive( byte[] data ) { 			// <-- default handler
 //void receive( byte[] data, String ip, int port ) {	// <-- extended handler

 for(int i=0; i < data.length; i++)
 print(char(data[i]));
 println();
 }
 */


