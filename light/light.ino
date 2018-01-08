//----------Start of libs----------
#include <WiFiUdp.h>
#include <ESP8266WiFi.h>
//----------End of libs----------



//----------Start of network settings----------
const char* ssid = "DESKTOP-066IE8G 4066";
const char* password = "janko888";
unsigned int localPort = 8888;      // port to listen on
IPAddress ip_pc(192, 168, 137, 1);  // gateway
WiFiUDP udp;  // instance to receive a send packet via UDP
int sequence_number = 0;
int packetSize = 0;
IPAddress remote_ip;
int remote_port;
char packet_buffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet,
//----------End of network settings----------



//----------Start of prepared msg----------
char reply_err_msg[] = "err msg, not identify type of msg";       // err msg
//----------End of prepared msg----------



//----------Start of cypher and shared secret----------
char auth_code[3] = "kp";  //special code for each device size of 2B
char public_key[33] = "TearcyojIbPetjut6Ossyakgetafwij6";
char private_key[33] = "FroneedbosghefmygNoghWyljirteirj";
//----------End of cypher and shared secret----------



//----------Start of function declaration----------
void connect_to_net_via_wifi();
void sensors_and_actuators_init();
void reg_and_auth();
int identify_packet();
void func_0();
void func_1();
void print_general_info();
int parse_packet();
void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg, int size_of_msg);
void default_function();
//----------End of function declaration----------



//----------Start of CODE----------
void connect_to_net_via_wifi()
{
  WiFi.begin(ssid, password);
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.println("WiFi connected");
}



void sensors_and_actuators_init()
{
  Serial.println("Start of S & A init");
  // code of special S & A
  Serial.println("End of S & A init");
}



void reg_and_auth()
{
  Serial.println("Start of reg and auth");
  // code of reg and auth of whole device to gateway
  Serial.println("End of reg and auth");
}



int identify_packet()
{
  int type_of_packet = -1;
  // get type of packet and return
  return type_of_packet;
}



void func_0()
{
  // something to DO
}



void func_1()
{
  // something to DO
}



void print_general_info()
{
  Serial.print("Received packet of size ");
  Serial.println(packetSize);
  
  Serial.print("From ");
  for (int i = 0; i < 4; i++)
  {
    Serial.print(remote_ip[i], DEC);
    if (i < 3)
    {
      Serial.print(".");
    }
  }

  Serial.print(", port ");
  Serial.println(remote_port);
}



int parse_packet()
{
  Serial.println("Start of parse packet");

  remote_ip = udp.remoteIP(); // read the packet remote IP
  remote_port = udp.remotePort(); // read the packet remote port
  udp.read(packet_buffer, UDP_TX_PACKET_MAX_SIZE); // read the packet into packetBufffer
  print_general_info();
  
  switch(identify_packet())
  {
   case 0 :
      func_0();
      break;
   case 1 :
      func_1();
      break;
   default :
   default_function();
}
  
  Serial.println("End of parse packet");

  if (true) // temporary to pass program
    return 1; //corect parse packet
  else
    return 0; //fail of parse packet
}



void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg, int size_of_msg)
{
   // send a reply, to the IP address and port that sent us the packet we received
      udp.beginPacket(dst_ip, dst_port);
      udp.write(msg);
      udp.endPacket();
      delay(10);
}



void default_function() // print receivd msg and send error msg back
{
  Serial.println("Start of default function");      
      
      Serial.println("Contents of packet:");
      for (int i = 0; i < packetSize; i++)
        Serial.print(packet_buffer[i]);
      Serial.println("");

      send_udp_msg(remote_ip, remote_port, reply_err_msg, sizeof(reply_err_msg));
  
  Serial.println("End of default function");
}



void setup()
{
  Serial.begin(9600); // serial start for help print to console
  delay(10);
  
  connect_to_net_via_wifi();  // connet to network
 
  udp.begin(localPort); // listen on port
  Serial.println("UDP listen");

  sensors_and_actuators_init();  // initial of modules - sensors, actuators
  reg_and_auth(); // registration of whole device to gateway
}



void loop()
{
  // start time for addition code e.g. call of funcion on relay, lamp, door lock
  Serial.println("Zaciatok cakania");
  delay(10000);
  Serial.println("Koniec cakania");
  // end time for addition code

  while (1) // listening UDP packets - commands, status and special calls and execution
  {
    packetSize = udp.parsePacket();
    if (packetSize) // if UDP packets come
    {
      parse_packet();
    }
    else
      break;
  }
}
//----------End of CODE----------
