//----------Start of libs----------
#include <WiFiUdp.h>
#include <ESP8266WiFi.h>
//----------End of libs----------



//----------Start of define----------
#define Light 14 // on Arduino UNO PIN 13 -> Wemos declarate as 14 - WEIRD :D
//----------End of define----------



//----------Start of network settings----------
const char* ssid = "DESKTOP-066IE8G 4066";
const char* password = "janko888";
unsigned int localPort = 8888;      // port to listen on
IPAddress ip_pc(192, 168, 137, 1);  // gateway
IPAddress remote_ip;
WiFiUDP udp;  // instance to receive a send packet via UDP
int sequence_number = 0;
int packetSize = 0;
int remote_port;
byte packet_buffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet
byte my_array[10]={-1,0,1,150,254,255,256,257,350,720};
byte ack_msg[6]={0,2,0,0,10,10};
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
byte identify_packet();
void print_general_info();
int parse_packet();
void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg);
void send_udp_msg(IPAddress dst_ip, int dst_port, byte msg[], byte size_of_msg);
void default_func();
void change_light_state(byte state);
void command_func();
int checksum_check();
int convert_byte_to_int(byte data[], byte start_index, byte data_size);
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



int convert_byte_to_int(byte data[], byte start_index, byte data_size)
{
    int result = 0;
    for (byte i = 0; i < data_size; i++)
  {
      byte pom = start_index + data_size - 1 - i;
      byte offset = 0;
      for (byte j = 0; j < i; j++)
      {
          offset += 8;
      }
      result += data[pom] << offset;
  }
  return result;
}



void sensors_and_actuators_init()
{
  pinMode(Light, OUTPUT);
}



void change_light_state(byte state)
{
  if (state)
    digitalWrite(Light, HIGH);
  else
    digitalWrite(Light, LOW);
}



void reg_and_auth()
{
  Serial.println("Start of reg and auth");
  // code of reg and auth of whole device to gateway
  Serial.println("End of reg and auth");
}



byte identify_packet()
{  
  return convert_byte_to_int(packet_buffer, 0, 2); // get type of packet and return
}



int checksum_check()
{
  return 1; //checksum check disabled
}



void command_func()
{
  Serial.print("Number of CMDS ");
  Serial.println(convert_byte_to_int(packet_buffer, 4, 1)); // return number of cmds  
  
  change_light_state(convert_byte_to_int(packet_buffer, 6, 1)); // change state of lamp
  send_udp_msg(remote_ip, remote_port, ack_msg, (sizeof(ack_msg))); // send ACK
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
  remote_ip = udp.remoteIP(); // read the packet remote IP
  remote_port = udp.remotePort(); // read the packet remote port
  udp.read(packet_buffer, UDP_TX_PACKET_MAX_SIZE); // read the packet into packetBufffer
  print_general_info();

  if (checksum_check())
  {
    switch(identify_packet())
    {
     case 1 :
        //register_response_func();
        break;
     case 2 :
        //acknowledgement_func();
        break;
     case 3 :
        //not_acknowledgement_func();
        break;
     case 4 :
        //authentication_func();
        break;
     case 6 :
        command_func();
        break;
     case 7 :
        //status_func();
        break;
     case 8 :
        //finish_func();
        break;
     default :
     default_func();
    }
  }
  else
    return 0; //fail of parse packet
    
  return 1; //corect parse packet
}



void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg)
{
   // send a reply, to the IP address and port that sent us the packet we received
      udp.beginPacket(dst_ip, dst_port);
      udp.write(msg);
      udp.endPacket();
      delay(10);
}



void send_udp_msg(IPAddress dst_ip, int dst_port, byte msg[], byte size_of_msg)
{
   // send a reply, to the IP address and port that sent us the packet we received
      udp.beginPacket(dst_ip, dst_port);
      udp.write(msg, size_of_msg);
      udp.endPacket();
      delay(10);
}



void default_func() // print receivd msg and send error msg back
{
      Serial.print("Default function, contents of packet: ");
      for (int i = 0; i < packetSize; i++)
        Serial.print(packet_buffer[i]);
      Serial.println("");

      send_udp_msg(remote_ip, remote_port, my_array, (sizeof(my_array)));
}



void setup()
{
  Serial.begin(9600); // serial start for help print to console
  delay(10);
  pinMode(LED_BUILTIN, OUTPUT);
  
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
