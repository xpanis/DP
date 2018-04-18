//----------Start of libs----------
#include <WiFiUdp.h>
#include <ESP8266WiFi.h>
#include <Curve25519.h>
#include <Speck.h>
//----------End of libs----------



//----------Start of define----------
#define Light 14 // on Arduino UNO PIN 13 -> Wemos declarate as 14 - WEIRD :D
#define port_pc 4444 //default port pc listen on
#define debug false  //true if debging.... false if correct program
#define generate_dfh false  //if false -> communicate with server via define keys
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
uint8_t state_of_device = 0;
byte *temp_msg;
uint8_t flag_of_success_reg_auth = 1;
bool have_gateway_pub_key = false;
bool have_salt = false;
//----------End of network settings----------



//----------Start of prepared msg----------
char reply_err_msg[] = "err msg, not identify type of msg";       // err msg
uint8_t * deciphered_packet;
//----------End of prepared msg----------



//----------Start of cypher and shared secret----------
uint8_t auth_code[2] = {23,138};  //special code for each device size of 2B
uint8_t salt_from_server[2];
uint8_t public_key_of_arduino[32];
uint8_t * public_key_of_server_or_ssecret;
uint8_t private_key[32];
Speck speck;

uint8_t fake_public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t fake_private_key[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};
//----------End of cypher and shared secret----------



//----------Start of function declaration----------
void connect_to_net_via_wifi();
void sensors_and_actuators_init();
void reg_and_auth();
byte identify_packet();
void print_general_info();
int parse_packet(byte type_of_packet_to_parse);
void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg);
void send_udp_msg(IPAddress dst_ip, int dst_port, byte msg[], byte size_of_msg);
void default_func();
void change_light_state(byte state);
void command_func();
int checksum_check();
int convert_byte_to_int(byte data[], byte start_index, byte data_size);
void alocate_msg_mem(byte **mem, uint8_t size_of_mem);
void convert_number_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t number_size, long number);
void convert_array_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t input_data_size, byte * input_data);
uint8_t * convert_array_of_bytes_to_array(byte data[], byte start_index, byte data_size);
void get_packet_to_buffer(bool need_decipher);
//----------End of function declaration----------

int incomingByte = 0; 

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


uint8_t * convert_array_of_bytes_to_array(byte data[], byte start_index, byte data_size) //get array from MSG array to arduino
{
  uint8_t * ret_array;
  ret_array = NULL;
  alocate_msg_mem(&ret_array, data_size);
  int j = start_index;
  for (int i = 0; i <  data_size; i++)
  {
    ret_array[i] = data[j];
    j++;
  }  
  return ret_array;
}


int convert_byte_to_int(byte data[], byte start_index, byte data_size) //get number from MSG array to arduino
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



void convert_number_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t number_size, long number) //set number from arduino to MSG array
{
  uint8_t size_of_temp_array = 1;
  long temp_number = number;
  
  while (temp_number >= 256)
  {
    size_of_temp_array++;
    temp_number = temp_number >> 8;
  }

  /*Serial.print("Number: ");
  Serial.println(number);
  
  Serial.print("Min size of number: ");
  Serial.println(size_of_temp_array);

  Serial.print("You choice number size: ");
  Serial.println(number_size);*/

  if (number_size >= size_of_temp_array)
  {
    //byte * temp_array = (byte *) malloc(number_size * sizeof(byte));
    temp_number = number;
    long divider = 1;
    for (int i = 0; i < (number_size - 1); i++)
    {
      divider = divider << 8;
    }
    
    for (int i = start_index; i < (start_index + number_size); i++)
    {
      data_array[i] = number / divider;
      /*Serial.print("Na poziciu: ");
      Serial.print(i);
      Serial.print(" ide cislo: ");
      Serial.println(data_array[i]);*/
      
      temp_number = data_array[i] * divider;
      number = number - temp_number;
      divider = divider >> 8;  
    }
  }
  else
    Serial.println("Cislo sa nezmesti do danych policok");
}


void convert_array_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t input_data_size, byte * input_data) //set array from arduino to MSG array
{
  int j = 0;
  for (int i= start_index; i < (start_index + input_data_size); i++)
  {
    //Serial.print("zapis cisla: ");
    //Serial.println(input_data[j]);
    convert_number_to_array_on_position(data_array, i, 1, input_data[j]);
    j++;
  }
}



void alocate_msg_mem(byte **mem, uint8_t size_of_mem)
{
  *mem = NULL;
  *mem = (byte *) malloc(size_of_mem * sizeof(byte));

 if(*mem == NULL)
  {
      free(*mem);
      Serial.println("Erro of allocation!");
  }
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
  while (flag_of_success_reg_auth)
  {
    switch(state_of_device)
      {
       case 0 : //send register msg
       {
          Serial.println("STAV");
          Serial.println(state_of_device);
          Serial.println("Start of generating keys");
          if (generate_dfh)
          {
            Serial.println("RLY generating keys");
            Curve25519::dh1(public_key_of_arduino, private_key); //generation of private and public key for DFH - ERROR when CURVE generate - works NOW
            
          }
          else
          {
            Serial.println("FAKE generating keys");
            for (int i = 0; i < 32; i++)
            {
              public_key_of_arduino[i] = fake_public_key_of_arduino[i];
              private_key[i] = fake_private_key[i];
            }
          }                   
          alocate_msg_mem(&temp_msg, 38);
          convert_number_to_array_on_position(temp_msg, 0, 2, 0); //set msg type 0
          convert_number_to_array_on_position(temp_msg, 2, 2, 1); //set seq_numbe into msg
          convert_array_to_array_on_position(temp_msg, 4, sizeof(public_key_of_arduino), public_key_of_arduino); //set public key into msg
          convert_number_to_array_on_position(temp_msg, 36, 2, 9); //set checksum into msg - USE CRC16 - to DO
          send_udp_msg(ip_pc, port_pc, temp_msg, 38); // send of registration packet
          state_of_device++;
          break;
       }
       case 1 : //wait for public key from server
       {
          Serial.println("STAV");
          Serial.println(state_of_device);
          uint8_t wait_times = 0;
          uint8_t cancel_flag = 0;
          while (!cancel_flag) // listening UDP register_response packets
          {
            packetSize = udp.parsePacket();
            if (packetSize) // if UDP packets come
            {
              get_packet_to_buffer(false);
              parse_packet(1);
              if (have_gateway_pub_key)
                {
                  Curve25519::dh2(public_key_of_server_or_ssecret, private_key);                  
                  state_of_device++;
                  cancel_flag = 1;
                  speck.setKey(public_key_of_server_or_ssecret, 32); //with calculated cipher via DFH and set Speck key
                }
                else
                  Serial.println("Come wrong packet - not register response");
            }
            else
            {
              if (wait_times < 10)  //wait 5 sec for public key of server, if not come set case 0
              {
                delay(500);
                wait_times++;
              }
              else  // in 5 sec after register not came register response -> packet lost -> send new register msf
              {
                state_of_device = 0; //repeat whole - case 0
                cancel_flag = 1;
              }
            }
          }
          break;
       }
       case 2 :
          Serial.println("STAV");
          Serial.println(state_of_device);
          send_udp_msg(remote_ip, remote_port, ack_msg, (sizeof(ack_msg))); // send ACK
          state_of_device++;
          break;
       case 3 : //wait for SALT - auth packet
          //start of secret communication - auth - via shared_secret
          {
            Serial.println("STAV");
            Serial.println(state_of_device);
            uint8_t wait_times = 0;
            uint8_t cancel_flag = 0;
            while (!cancel_flag) // listening UDP register_response packets
            {
              packetSize = udp.parsePacket();
              if (packetSize) // if UDP packets come
              {
                get_packet_to_buffer(true);
                parse_packet(4);
                if (have_salt)
                  {
                    state_of_device++;
                    cancel_flag = 1;
                  }
                  else
                    Serial.println("Come wrong packet - not authentification");
              }
              else
              {
                if (wait_times < 10)  //wait 5 sec for salt, if not come set case 0
                {
                  delay(500);
                  wait_times++;
                }
                else  // in 5 sec after register not came register response -> packet lost -> send new register msf
                {
                  state_of_device = 0; //repeat whole - case 0
                  cancel_flag = 1;
                }
              }
            }            
            state_of_device++;
            break;
          }
       case 4 :
          Serial.println("STAV");
          Serial.println(state_of_device);
          state_of_device++;
          break;
       case 5 :
          Serial.println("STAV");
          Serial.println(state_of_device);
          state_of_device++;
          flag_of_success_reg_auth = 0;
          break;
       default :
       ;
      }
  }
}



byte identify_packet() //need chceck - work only with second byte!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!***********************************
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



void get_packet_to_buffer(bool need_decipher)
{
  remote_ip = udp.remoteIP(); // read the packet remote IP
  remote_port = udp.remotePort(); // read the packet remote port
  udp.read(packet_buffer, UDP_TX_PACKET_MAX_SIZE); // read the packet into packetBufffer

  if (need_decipher)
  {
    free(deciphered_packet);
    deciphered_packet = (uint8_t *) malloc(packetSize * sizeof(uint8_t));    
    speck.decryptBlock(deciphered_packet, packet_buffer);    
    for (int i = 0; i < packetSize; i++)
    {
      packet_buffer[i] = deciphered_packet[i];
    }
  }
}



int parse_packet(byte type_of_packet_to_parse) // 0 - for all
{
  print_general_info();

  if (checksum_check())
  {
    int parse_permition = identify_packet();
    //Serial.println("parse permition is: ");
    //Serial.println(parse_permition);
    if ((type_of_packet_to_parse == 0) || (type_of_packet_to_parse == parse_permition))
    {    
      switch(parse_permition)
      {
       case 1 :
          alocate_msg_mem(&public_key_of_server_or_ssecret, 32);
          public_key_of_server_or_ssecret = convert_array_of_bytes_to_array(packet_buffer, 4, 32);
          Serial.println("get_this_public");
          for(int i = 0; i < 32; i++)
          {
            Serial.print(public_key_of_server_or_ssecret[i]);
            Serial.print(", ");
          }
          Serial.print("");
          have_gateway_pub_key = true;
          break;
       case 2 :
          //acknowledgement_func();
          break;
       case 3 :
          //not_acknowledgement_func();
          break;
       case 4 :
          //authentication_func();
          salt_from_server[0] = packet_buffer[4];
          salt_from_server[1] = packet_buffer[5];
          Serial.print("salt is: ");
          Serial.print(salt_from_server[0]);
          Serial.print(", ");
          Serial.print(salt_from_server[1]);
          Serial.println("");          
          have_salt = true;
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
    {
      Serial.println("Invalid permission for parse packet!");
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

  if (!debug)
  {
  connect_to_net_via_wifi();  // connet to network
 
  udp.begin(localPort); // listen on port
  Serial.println("UDP listen");

  sensors_and_actuators_init();  // initial of modules - sensors, actuators
  reg_and_auth(); // registration of whole device to gateway
  Serial.println("Koniec reg_and auth");
  }
  else
  {
    //test
  }
}



void loop()
{
  if (!debug)
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
        get_packet_to_buffer(false); // neskor TRUE!!!!
        parse_packet(0);
      }
      else
        break;
    }
  }
  else
  {
  //test
  }
}
//----------End of CODE----------
