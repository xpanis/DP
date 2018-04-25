//----------Start of libs----------
#include <WiFiUdp.h>
#include <ESP8266WiFi.h>
#include <Curve25519.h>
#include <Speck.h>
#include <BLAKE2s.h>
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
int expected_seq_number = 0;
int sequence_number = 0;
int packetSize = 0;
int remote_port;
byte packet_buffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet
byte my_array[10]={-1,0,1,150,254,255,256,257,350,720};
byte ack_msg[6]={0,2,0,0,10,10};
uint8_t state_of_device = 0;
byte *raw_packet;
byte *temp_msg;
byte *temp_msg_to_cipher;
uint8_t flag_of_success_reg_auth = 1;
bool have_gateway_pub_key = false;
bool have_salt = false;
bool come_ack = false;
bool come_nack = false;
uint8_t number_of_16_u_arrays = 0;
int seq_number = 0;
uint16_t * packet_to_checksum;
int size_of_packet = 0;
bool register_completed = false;
//int number_of_16_u_arrays = 0;
//----------End of network settings----------



//----------Start of prepared msg----------
char reply_err_msg[] = "err msg, not identify type of msg";       // err msg
uint8_t * deciphered_packet;
uint8_t ** input_parts_of_packet;
uint8_t ** output_parts_of_packet;
//----------End of prepared msg----------



//----------Start of cypher and shared secret----------
uint8_t auth_code[8] = {23, 138, 57, 62, 241, 37, 85, 11};  //special code for each device
uint8_t salt_from_server[8];
uint8_t salted_code[8];
uint8_t public_key_of_arduino[32];
uint8_t * public_key_of_server_or_ssecret;
uint8_t private_key[32];
uint8_t key_for_blake[32];
Speck speck;

uint8_t fake_public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t fake_private_key[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};
//----------End of cypher and shared secret----------



//----------Start of function declaration----------
void connect_to_net_via_wifi();
void sensors_and_actuators_init();
void reg_and_auth();
int identify_packet();
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
uint16_t sum_calc(uint16_t lenght, uint16_t * input);
int create_packet(byte ** packet_to_ret, byte * payload, int size_of_payload, bool is_crypted, int type, int seq_number);
int number_of_words_is(int size_of_payload);
void stop_function();
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



uint16_t sum_calc(uint16_t lenght, uint16_t * input)
{
  uint16_t word16 = 0;
  uint32_t sum = 0;
  
  for (uint16_t i = 0; i < lenght; i = i + 2)
  {
    word16 =(((input[i]<<8)&0xFF00) + (input[i+1]&0xFF));
    sum = sum + (uint32_t) word16;
  }
  while (sum>>16)
  {
    sum = (sum & 0xFFFF)+(sum >> 16);
  }
  
sum = ~sum;
return ((uint16_t) sum);
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
        result += (data[pom] << offset);
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



int number_of_words_is(int size_of_payload)
{
  size_of_payload += 4;
  int ret = 0;
  int part = 0;
  int rest = 0;
  part = size_of_payload / 16;
  rest = size_of_payload % 16;
  ret = part;
  if (rest > 0)
    ret++;
  return ret;
}



int create_packet(byte ** packet_to_ret, byte * payload, int size_of_payload, bool is_crypted, int type, int seq_number)
{
  Serial.println("In create packet: 1");
  int size_of_whole_packet = 0;
  *packet_to_ret = NULL;
  byte * msg;
  msg = *packet_to_ret;
  Serial.println("In create packet: 2");
  free(msg);
  Serial.println("In create packet: 3");
  
  if (is_crypted) //tu niekde to crashuje
  {
    number_of_16_u_arrays = number_of_words_is(size_of_payload);
    int size_of_temp_msg_to_cipher = size_of_payload + 4;
    alocate_msg_mem(&msg, ((16 * number_of_16_u_arrays) + 2));
    *packet_to_ret = msg;
    alocate_msg_mem(&temp_msg_to_cipher, size_of_temp_msg_to_cipher); //sign of size of payload: type + seq + 32bytes of hash
    input_parts_of_packet = (uint8_t **) malloc(number_of_16_u_arrays * sizeof(uint8_t)); //allocate x times word (16bytes block) to cipher: input + output
    output_parts_of_packet = (uint8_t **) malloc(number_of_16_u_arrays * sizeof(uint8_t));
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      input_parts_of_packet[i] = (uint8_t *) malloc(16 * sizeof(uint8_t));
      output_parts_of_packet[i] = (uint8_t *) malloc(16 * sizeof(uint8_t));
    }
    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      for (int j = 0; j < 16; j++)
      {
        input_parts_of_packet[i][j] = 0;
        output_parts_of_packet[i][j] = 0;
      }
    }
    
    convert_number_to_array_on_position(temp_msg_to_cipher, 0, 2, type);
    convert_number_to_array_on_position(temp_msg_to_cipher, 2, 2, (long) seq_number);
    convert_array_to_array_on_position(temp_msg_to_cipher, 4, size_of_payload, payload); //set public key into msg
    int index = 0;
    int stop_index = 16;
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      for (; index < stop_index; index++)
      {
        if (index < size_of_temp_msg_to_cipher)
        {
          input_parts_of_packet[i][index - (i * 16)] = temp_msg_to_cipher[index];
        }
      }
      stop_index += 16;
    }

    Serial.println("In input after fill is: ");
    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      Serial.print("Pole ");
      Serial.print(i);
      Serial.print(" is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(input_parts_of_packet[i][j]);
        Serial.print(", ");
      }
    }
    Serial.println("");
    Serial.println("");
    
    free(temp_msg_to_cipher);
    speck.setKey(public_key_of_server_or_ssecret, 32); //with calculated cipher via DFH and set Speck key
    Serial.println("I: ");
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      Serial.print(i);
      Serial.print(", ");
      Serial.println("");
      speck.encryptBlock(&output_parts_of_packet[i][0], &input_parts_of_packet[i][0]);  //CRASHER HERE in i = 2; when come AUTH
      Serial.print("Ciphered is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(output_parts_of_packet[i][j]);
        Serial.print(", ");
      }
      Serial.print(" Encrypt OK! ");
      Serial.println("");
    }
    Serial.println("");
    Serial.println("In create packet: 14");
    index = 0;
    stop_index = 16;
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      for (; index < stop_index; index++)
      {
        msg[index] = output_parts_of_packet[i][index - (i * 16)];
      }
      stop_index += 16;
    }
    Serial.println("In create packet: 15");

    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      input_parts_of_packet[i] = NULL;
      output_parts_of_packet[i] = NULL;
      free(input_parts_of_packet[i]);
      free(output_parts_of_packet[i]);
    }
    Serial.println("In create packet: 16");
    input_parts_of_packet = NULL;
    free(input_parts_of_packet);
    Serial.println("In create packet: 17");
    output_parts_of_packet = NULL;
    free(output_parts_of_packet);    
    Serial.println("In create packet: 18");
    packet_to_checksum =  (uint16_t *) malloc((number_of_16_u_arrays * 16) * sizeof(uint16_t)); //CRASHER HERE in i = 2; when come AUTH
    Serial.println("In create packet: 19");
    for (int i = 0; i < (number_of_16_u_arrays * 16); i++)
    {
      packet_to_checksum[i] = (uint16_t) msg[i];
    }
    Serial.println("In create packet: 20");
    uint16_t checksum = sum_calc((number_of_16_u_arrays * 16), packet_to_checksum);
    Serial.println("In create packet: 21");
    packet_to_checksum = NULL;
    free(packet_to_checksum);   
    Serial.println("In create packet: 22"); 
    convert_number_to_array_on_position(msg, (number_of_16_u_arrays * 16), 2, (long) checksum); //set checksum into msg
    Serial.println("In create packet: 23");
    size_of_whole_packet = (16 * number_of_16_u_arrays) + 2;
    Serial.println("In create packet: 24");
  }
  else
  {
    Serial.println("In create packet: 25");
    alocate_msg_mem(&msg, (size_of_payload + 6));
    *packet_to_ret = msg;
    
    convert_number_to_array_on_position(msg, 0, 2, type);
    convert_number_to_array_on_position(msg, 2, 2, (long) seq_number);
    convert_array_to_array_on_position(msg, 4, size_of_payload, payload); //set public key into msg
    packet_to_checksum =  (uint16_t *) malloc((size_of_payload + 4) * sizeof(uint16_t));
    for (int i = 0; i < (size_of_payload + 4); i++)
    {
      packet_to_checksum[i] = (uint16_t) msg[i];
    }
    uint16_t checksum = sum_calc((size_of_payload + 4), packet_to_checksum);
    packet_to_checksum = NULL;
    free(packet_to_checksum);    
    convert_number_to_array_on_position(msg, (size_of_payload + 4), 2, (long) checksum); //set checksum into msg
    size_of_whole_packet = (size_of_payload + 6);
    Serial.println("In create packet: 26");
  }
  return size_of_whole_packet;
}



void reg_and_auth()
{
  register_completed = false;
  while (flag_of_success_reg_auth)
  {
    switch(state_of_device)
      {
       case 0 : //send register msg
       {
          if (generate_dfh)
          {
            Serial.println("RLY generating keys!");
            Curve25519::dh1(public_key_of_arduino, private_key);
          }
          else
          {
            Serial.println("FAKE generating keys!");
            for (int i = 0; i < 32; i++)
            {
              public_key_of_arduino[i] = fake_public_key_of_arduino[i];
              private_key[i] = fake_private_key[i];
            }
          }
          //free(temp_msg);
          seq_number = 1;
          size_of_packet = create_packet(&temp_msg, public_key_of_arduino, sizeof(public_key_of_arduino), false, 0, seq_number);
          send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet);
          state_of_device++;
          break;
       }
       case 1 : //wait for public key from server
       {
          Serial.println("STATE 1");
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
                  have_gateway_pub_key = false;
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
       {
          Serial.println("STATE 2");
          //free(temp_msg);
          seq_number = 1;
          size_of_packet = create_packet(&temp_msg, NULL, 0, true, 2, seq_number);
          send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
          //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet); - The Real One
          state_of_device++;
          break;
       }
       case 3 : //wait for SALT - auth packet
       {
        Serial.println("STATE 3");
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
                  have_salt = false;
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
          break;
       }
       case 4 : //have salt, calculate hash and send auth_response  
          {
            Serial.println("STATE 4");
            /*BLAKE2s blake;
            blake.reset(key_for_blake, sizeof(key_for_blake), 32);
            blake.update(salted_code, sizeof(salted_code));
            uint8_t hashed_auth_code[32];
            blake.finalize(hashed_auth_code, 32);*/
            BLAKE2s blake;
            blake.resetHMAC(key_for_blake, sizeof(key_for_blake));
            blake.update(salted_code, sizeof(salted_code));
            uint8_t hashed_auth_code[32];
            blake.finalizeHMAC(key_for_blake, sizeof(key_for_blake), hashed_auth_code, 32);
            
            Serial.print("HASH after Blake2s: ");
            for (int i = 0; i < 32; i++)
            {
              Serial.print(hashed_auth_code[i]);
              Serial.print(", ");
            }
            Serial.println("");
            Serial.println("");

            //free(temp_msg);
            seq_number++;
            Serial.print("1");
            size_of_packet = create_packet(&temp_msg, hashed_auth_code, sizeof(hashed_auth_code), true, 5, seq_number);
            Serial.print("2");
            seq_number++;
            expected_seq_number = seq_number;
            Serial.print("3");
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
            Serial.print("4");
            //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet); - The Real One
            state_of_device++;
            Serial.print("5");
            break;
          }
       case 5 :
          {
            Serial.println("STATE 5");
            //seq number from packet must == seq_number;
            //wait for acknoladge / notack
            uint8_t wait_times = 0;
            uint8_t cancel_flag = 0;
            while (!cancel_flag) // listening UDP register_response packets
            {
              packetSize = udp.parsePacket();
              if (packetSize) // if UDP packets come
              {
                get_packet_to_buffer(true);
                int parse_permition = identify_packet();
                parse_packet((byte) parse_permition);
                if (come_ack)
                {
                  cancel_flag = 1;
                  flag_of_success_reg_auth = 0;
                  come_ack = false;
                }
                else
                {
                  if (come_nack)
                  {
                    cancel_flag = 1;
                    come_nack = false;
                    state_of_device = 0;
                  }
                  else
                  {
                    Serial.println("Come wrong packet - not ack or nack");
                  }
                }
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
            break;
         }
       default :
       ;
      }
  }
  register_completed = true;
  Serial.println("Register and Authentication is successfull!");
}



int identify_packet()
{  
  return convert_byte_to_int(packet_buffer, 0, 2); // get type of packet and return
}



int checksum_check()
{
  packet_to_checksum =  (uint16_t *) malloc((packetSize - 2) * sizeof(uint16_t));
  int packet_size_shorted = packetSize - 2;
  
  for (int i = 0; i < (packet_size_shorted); i++)
  {
    packet_to_checksum[i] = (uint16_t) raw_packet[i];
  }
  
  uint16_t calc_checksum = sum_calc(packet_size_shorted, packet_to_checksum);  
  free(packet_to_checksum);
  free(raw_packet);  
  int get_checksum = convert_byte_to_int(raw_packet, packet_size_shorted, 2);
    
  if (get_checksum == (int) calc_checksum)
  {
    Serial.println("Checksum PASS");
    return 1;
  }
  Serial.println("Checksum NOT PASS");
  return 0;
}



void command_func()
{
  Serial.print("Number of CMDS ");
  Serial.println(convert_byte_to_int(packet_buffer, 4, 1)); // return number of cmds  
  
  change_light_state(convert_byte_to_int(packet_buffer, 6, 1)); // change state of lamp
  seq_number++;
  size_of_packet = create_packet(&temp_msg, NULL, 0, true, 2, seq_number);
  //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet);
  send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
  //send_udp_msg(remote_ip, remote_port, ack_msg, (sizeof(ack_msg))); // send ACK
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
  alocate_msg_mem(&raw_packet, packetSize);
  Serial.println("Packet in get_packet_to_buffer");
  for (int i = 0; i < packetSize; i++)
  {
    raw_packet[i] = packet_buffer[i];
  }
  Serial.println("here 1");
  if (need_decipher)
  {
    Serial.println("here 2");
    deciphered_packet = (uint8_t *) malloc(packetSize * sizeof(uint8_t));
    Serial.println("here 3");    
    speck.decryptBlock(deciphered_packet, packet_buffer); 
    Serial.println("here 4");   
    Serial.print("Deciphered packet: ");
    for (int i = 0; i < packetSize; i++)
    {
      packet_buffer[i] = deciphered_packet[i];
      Serial.print(packet_buffer[i]);
      Serial.print(", ");
    }
    Serial.println("");
    Serial.println("here 5"); 
    deciphered_packet = NULL;
    free(deciphered_packet);
    Serial.println("here 6"); 
  }
  Serial.println("Packet in get_packet_to_buffer OUT");
}



int parse_packet(byte type_of_packet_to_parse) // 0 - for all
{
  Serial.println("In parse packet");
  print_general_info();
  if (checksum_check())
  {
    int parse_permition = identify_packet();
    if ((type_of_packet_to_parse == 0) || (type_of_packet_to_parse == parse_permition))
    {    
      switch(parse_permition)
      {
       case 1 :
       {
          if (!register_completed) //register mode
          {
            alocate_msg_mem(&public_key_of_server_or_ssecret, 32);
            public_key_of_server_or_ssecret = convert_array_of_bytes_to_array(packet_buffer, 4, 32);
            for(int i = 0; i < 32; i++)
            have_gateway_pub_key = true;
          }
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 2 : //acknowledgement_func();
       {
          if (!register_completed) //register mode
          {
            if (convert_byte_to_int(packet_buffer, 2, 2) == expected_seq_number)
            {
              come_ack = true;
            }
          }
          else
          {
            //in normal mode DO ST - WHEN I SEND DATA... I HAVE TO WAIT FOR ACK - TO DO
            //When I send FIN - I WAIT TO SHUT DOWN - HAVE TO WAIT ACK
          }          
          break;
       }
       case 3 : //not_acknowledgement_func();
       {
          if (!register_completed) //register mode
          {
            if (convert_byte_to_int(packet_buffer, 2, 2) == expected_seq_number)
            {
              come_nack = true;
            }
          }
          else
          {
            //in normal mode DO ST
            //When I send FIN - I WAIT TO SHUT DOWN - IF SERVER SEND ME NACK I INTERRUPT STOPPING
          }
          break;
       }
       case 4 : //authentication_func();
       {
          if (!register_completed) //register mode
          {
            Serial.print("Salt come: ");
            for (int i = 0; i < 8; i++)
            {
              salt_from_server[i] = packet_buffer[i + 4];
              Serial.print(salt_from_server[i]);
              Serial.print(", ");
            }
            Serial.println("");
            Serial.println("");
            
            Serial.print("Auth CODE of Arduino is: ");
            for (int i = 0; i < 8; i++)
            {
              Serial.print(auth_code[i]);
              Serial.print(", ");
            }
            Serial.println("");
            Serial.println("");
            
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            Serial.print("Get SEQ number: ");
            Serial.print(seq_number);
            Serial.println("");
            Serial.println("");

            Serial.print("Xored is: ");
            for (int i = 0; i < 8; i++)
            {
              salted_code[i] = (auth_code[i] ^ salt_from_server[i]);
              Serial.print(salted_code[i]);
              Serial.print(", ");
            }
            Serial.println("");
            Serial.println("");
            
            have_salt = true;
          }
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 5 : //mistake
       {
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 6 : //COMMAND
       {
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            command_func(); //TO DO!!!!!!!!!!!!!!!!!!!!!!!!
          }
          break;
       }
       case 7 : //STATUS
       {
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
         }
         else
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 2, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);     
            //status_func();
            //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
         }
         break;
       }
       case 8 : //FINISH
       {
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
         }
         else
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 2, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);          
            stop_function();
           //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
           //STOP DEVICE
         }
         break;
       }
       default :  //DATA
       {
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(&temp_msg, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            default_func();
            seq_number = 1; //TO DO
            size_of_packet = create_packet(&temp_msg, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
       }
      }
    }
    else
    {
      Serial.println("Invalid permission for parse packet!");
    }
  }
  else
  {
    return 0; //fail of parse packet
  }    
  return 1; //corect parse packet
}



void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg)
{
   // send a reply, to the IP address and port that sent us the packet we received
      Serial.println("idem posielat");
      Serial.print("dest IP: ");
      Serial.print(dst_ip);
      Serial.println("");
      Serial.print("dest PORT: ");
      Serial.print(dst_port);
      Serial.println("");
      udp.beginPacket(dst_ip, dst_port);
      udp.write(msg);
      udp.endPacket();
      delay(10);
      Serial.println("koniec posielania");
}



void send_udp_msg(IPAddress dst_ip, int dst_port, byte msg[], byte size_of_msg)
{
   // send a reply, to the IP address and port that sent us the packet we received
      Serial.println("idem posielat");
      Serial.print("dest IP: ");
      Serial.print(dst_ip);
      Serial.println("");
      Serial.print("dest PORT: ");
      Serial.print(dst_port);
      Serial.println("");
      Serial.print("msg SIZE:");
      Serial.print(size_of_msg);
      Serial.println("");
      Serial.print("msg is:");
      for (int i = 0; i < size_of_msg; i++)
      {
        Serial.print(msg[i]);
        Serial.print(", ");
      }
      Serial.println("");
      udp.beginPacket(dst_ip, dst_port);
      udp.write(msg, size_of_msg);
      udp.endPacket();
      delay(10);
      Serial.println("koniec posielania");
}



void default_func() // print receivd msg and send error msg back
{
      Serial.print("Default function, contents of packet: ");
      for (int i = 0; i < packetSize; i++)
        Serial.print(packet_buffer[i]);
      Serial.println("");
}



void stop_function()
{
  while(1)
  {
    Serial.println("Program STOPPED, for restart: RESET ARDUINO!");
    delay(10000);
  }
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
  else  //test
  {
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
    while (1)
    {
      packetSize = udp.parsePacket();
      if (packetSize) // if UDP packets come
      {
        Serial.println("Packet come!");
        get_packet_to_buffer(true);
        int parse_permition = identify_packet();
        parse_packet((byte) parse_permition);
      }
      else
      {
        break;
      }
    }
  }
  else
  {
  //test
  }
}
//----------End of CODE----------
