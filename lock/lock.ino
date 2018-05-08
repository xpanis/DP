//----------Start of libs----------
#include <EthernetUdp.h>
#include <Ethernet.h>
#include <Curve25519.h>
#include <Speck.h>
#include <BLAKE2s.h>
#include <SPI.h>
#include <MFRC522.h>
//----------End of libs----------


//----------Start of define----------
#define cs_rfid 9
#define rst_rfid 8
#define cs_ethernet 10
#define debug false  //true if debging.... false if correct program
#define generate_dfh false  //if false -> communicate with server via define keys
#define UDP_TX_PACKET_MAX_SIZE 600
//----------End of define----------



//----------Start of network settings mine----------
unsigned int port_pc = 8888;        // port of gateway listen on
IPAddress ip_arduino(192, 168, 137, 177);  // IP of Arduino
IPAddress ip_pc(192, 168, 137, 1);  // IP of gateway
unsigned int localPort = 4444;      // port of esp8266 listen on
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
unsigned int remote_port;
IPAddress remote_ip;
EthernetUDP udp;  // instance to receive a send packet via UDP
//----------End of network settings----------



//----------Start of Fields----------
byte packet_buffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet
uint8_t input_parts_of_packet_static[6][16];
uint8_t output_parts_of_packet_static[6][16];
uint16_t packet_to_checksum_static[96];
byte raw_packet_static[98];
byte temp_msg_static[98];
//----------End of Fields----------



//----------Start of Buffers----------
byte buffer_temp_msg_static[6][98];
byte buffer_help[6][6];
byte sheduling_table[10][7];
byte cmd_help[10][3];
//----------End of Buffers----------



//----------Start of Variables----------
int expected_seq_number = 0;
int act_seq_number = 0;
int seq_number = 0;
uint8_t state_of_device = 0;
uint8_t number_of_16_u_arrays = 0;
int packetSize = 0;
int size_of_packet = 0;

MFRC522 rfid(cs_rfid, rst_rfid);
MFRC522::MIFARE_Key key; 
int code[] = {0,115,18,124}; //This is the stored UID
int codeRead = 0;
String uidString;
//----------End of Variables----------



//----------Start of Flags----------
bool flag_of_success_reg_auth = true;
bool have_gateway_pub_key = false;
bool have_salt = false;
bool come_ack = false;
bool come_nack = false;
bool register_completed = false;
bool flag_of_random = true;
//----------End of Flags----------



//----------Start of Timer Variables----------
unsigned int seconds = 0;
unsigned int minutes = 0;
unsigned long timeNow = 0;
unsigned long timeLast = 0;
unsigned int last_minute = 0;
//----------End of Timer variables----------



//----------Start of cypher and shared secret----------
uint8_t auth_code[8] = {23, 138, 57, 62, 241, 37, 85, 11};  //special code for each device
uint8_t salt_from_server[8];
uint8_t salted_code[8];
uint8_t public_key_of_arduino[32];
uint8_t private_key_of_arduino[32];
uint8_t public_key_of_server_or_ssecret_static[32];
uint8_t key_for_blake[32];
uint8_t fake_public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t fake_private_key[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};
uint8_t fake_public_key_of_server[32] = {174, 243, 69, 129, 50, 14, 32, 63, 61, 38, 104, 233, 157, 59, 18, 146, 231, 38, 134, 104, 218, 18, 237, 151, 178, 213, 104, 139, 155, 21, 222, 119}; //just for test withou auth phase
Speck speck;
//----------End of cypher and shared secret----------



//----------Start of Init function declaration----------
void connect_to_net_via_wifi();
void sensors_and_actuators_init();
void shedulling_table_init();
void buffer_init();
void reg_and_auth();
//----------End of Init function declaration----------



//----------Start of function for sending data declaration----------
void send_udp_msg(IPAddress dst_ip, int dst_port, char *msg);
void send_udp_msg(IPAddress dst_ip, int dst_port, byte msg[], byte size_of_msg);
int create_packet(byte * packet_to_ret, byte * payload, int size_of_payload, bool is_crypted, int type, int seq_number);
int number_of_words_is(int size_of_payload);
void retransmission();
void sequence_number_generator();
//----------End of function for sending data declaration----------



//----------Start of function for parse data declaration----------
int identify_packet();
void get_packet_to_buffer(bool need_decipher);
int parse_packet(byte type_of_packet_to_parse);
int checksum_check();
uint16_t sum_calc(uint16_t lenght, uint16_t * input);
//----------End of function for parse data declaration----------



//----------Start of buffers function declaration----------
void push_to_buffer(byte input_data[], byte size_of_input_data, int seq_number, bool is_fin);
bool clean_from_buffer(int expected_seq_number, bool * is_fin);
void sort_help_buffer();
void push_cmd_to_buffer(int _item, int _value1, byte _value2, int _time);
void do_command_from_sheduling_table();
//----------End of buffers function declaration----------



//----------Start of data prepare function declaration----------
int convert_byte_to_int(byte data[], byte start_index, byte data_size);
void convert_number_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t number_size, long number);
void convert_array_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t input_data_size, byte * input_data);
void convert_array_of_bytes_to_array(uint8_t output_data[], byte output_data_size, byte input_data[], byte start_index, byte input_data_size);
void prepare_number_to_data_msg(float input_number, byte * rest_output, long * number_output);
float get_float_from_cmd_format(int input_number, byte input_rest);
//----------End of data prepare function declaration----------



//----------Start of Sensors and actuators function declaration----------
void change_light_state(byte state);
void set_command();
void stop_function();
//----------End of Sensors and actuators function declaration----------



//----------Start of default and periodic function declaration----------
void default_func();
void print_general_info();
void do_periodic_func();
void timer();
//----------End of default and periodic function declaration----------



//----------Start of CODE----------
void readRFID()
{  
  rfid.PICC_ReadCardSerial();
  MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
   
  Serial.println("Scanned PICC's UID:");

  uidString = String(rfid.uid.uidByte[0])+" "+String(rfid.uid.uidByte[1])+" "+String(rfid.uid.uidByte[2])+ " "+String(rfid.uid.uidByte[3]);
  
  int i = 0;
  boolean match = true;
  
  while(i<rfid.uid.size)
  {
    if(!(rfid.uid.uidByte[i] == code[i]))
    {
         match = false;
    }
    i++;
  }

  Serial.println("");

  if(match)
  {
    Serial.println("I know this card!");
  }else
  {
    Serial.println("Unknown Card");
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}



void ss_modes()
{
  pinMode(cs_rfid, OUTPUT);
  pinMode(cs_ethernet, OUTPUT);
}



void rfid_disable_eth_enable()
{
  digitalWrite(cs_rfid, HIGH);
  digitalWrite(cs_ethernet, LOW);
}



void rfid_enable_eth_disable()
{
  digitalWrite(cs_ethernet, HIGH);
  digitalWrite(cs_rfid, LOW);
}



float get_float_from_cmd_format(int input_number, byte input_rest)
{
  float output_number = 0;
  if (input_rest < 100)
  {
    output_number += (float) (input_rest / 100);
    output_number += (float) (input_number);
  }
  else
  {
    input_rest = input_rest - 100;
    output_number += (float) (input_rest / 100);
    output_number += (float) (input_number);
    output_number *= (-1);
  }
  return output_number;
}



void sequence_number_generator()
{
  if ((flag_of_random) && (generate_dfh))
  {
    randomSeed(analogRead(0));
    act_seq_number = (random(16384)) * 2;
    flag_of_random = false;
  }
  else
  {
    act_seq_number += 2;
    act_seq_number = act_seq_number % 32768;
  }
  seq_number = act_seq_number;
  expected_seq_number = seq_number + 1;
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


void prepare_number_to_data_msg(float input_number, byte * rest_output, long * number_output)
{
  *rest_output = 0;
  *number_output = 0;
  long value_without_rest = 0;  
  byte adding_to_value = 0;
  
  if (input_number < 0)
  {
    input_number = input_number * (-1);
    adding_to_value += 100;
  }
  value_without_rest = (long) input_number;
  *number_output = value_without_rest;
  *rest_output = round((input_number - value_without_rest) * 100) + adding_to_value;
}



void do_periodic_func() //measure value from sensor and if is right time, send it as Data packet  //for test hard DATA:
{
  rfid_enable_eth_disable();
  
  if(rfid.PICC_IsNewCardPresent())
  {
      readRFID();
  }
  delay(100);
  
  rfid_disable_eth_enable();
}


void timer()
{
  Serial.println("in timer");
  timeNow = millis()/1000;
  seconds = timeNow - timeLast;

  if (seconds >= 60)
  {
  timeLast = timeNow;
  minutes = minutes + 1;
  }

  if (last_minute < minutes)
  {
   Serial.println("**************SPECIAL TIME***************");
   last_minute = minutes;
   do_command_from_sheduling_table();
   retransmission();
  }
  Serial.println("out timer");
}



void shedulling_table_init()
{
  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 7; j++)
    {
      sheduling_table[i][j] = 0;
      if (j < 3)
      {
        cmd_help[i][j] = 0;
      }
    }
  }
}


void buffer_init()
{
  for (int i = 0; i < 6; i++)
  {
    for (int j = 0; j < 98; j++)
    {
      buffer_temp_msg_static[i][j] = 0;
      if (j < 6)
      {
        buffer_help[i][j] = 0;
      }
    }
  }
}




void retransmission()
{
  Serial.println("Do retransmission");
  for (int i = 0; i < 6 ; i++)
  {
    if (buffer_help[i][0] != 0)
    {
      Serial.println("Send retransmission");
      Serial.println(i);
      send_udp_msg(ip_pc, port_pc, &buffer_temp_msg_static[i][0], buffer_help[i][0]); //can be remote IP and PORT
      for (int j = 0; j < 98; j++)
      {
        buffer_temp_msg_static[i][j] = 0;
        if (j < 6)
        {
          buffer_help[i][j] = 0;
        }
      }
    }
  }
}




void push_to_buffer(byte input_data[], byte size_of_input_data, int seq_number, bool is_fin) //only DATA + FIN!
{
  byte free_place_do_input_data = 100;
  
  for (int i = 0; i < 6; i++)
  {
    if (buffer_help[i][0] == 0) // found place for data
    {
      free_place_do_input_data = i;
      buffer_help[free_place_do_input_data][4] = 1;
      break;
    }
  }
  
  if (free_place_do_input_data == 100)  //  not found place -> remove oldest
  {
    for (int i = 0; i < 6 ; i++)
    {
      if (buffer_help[i][1] == 6) // the oldest one
      {
        free_place_do_input_data = i; // attach removed place
        for (int j = 0; j < 98; j++)
        {
          buffer_temp_msg_static[free_place_do_input_data][j] = 0; // clean of removed place
        }
        buffer_help[free_place_do_input_data][1] = 0;
      }
    }
  }

  for (int i = 0; i < 6 ; i++)
  {
    if (buffer_help[i][4] == 1) // uses at least one time
    {
      buffer_help[i][1]++;
    }
  }

  for (int i = 0; i < 98; i++)  //  fill buffer
  {
    buffer_temp_msg_static[free_place_do_input_data][i] = input_data[i];
  }
  
  buffer_help[free_place_do_input_data][0] = size_of_input_data;
  buffer_help[free_place_do_input_data][5] = (is_fin == true) ? 1: 0;
  convert_number_to_array_on_position(buffer_help[free_place_do_input_data], 2, 2, expected_seq_number);

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis buffer table: ");
  for (int i = 0; i < 6; i++)
  {
    for (int j = 0; j < 20; j++)
    {
      Serial.print(buffer_temp_msg_static[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Help Buffer table: ");
  for (int i = 0; i < 6; i++)
  {
    for (int j = 0; j < 6; j++)
    {
      Serial.print(buffer_help[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }
}



void sort_help_buffer()
{
  byte act_number = 1;
  bool is_this_number_in_buffer = false;
  byte missing_number = 1;
  
  for (int j = 0; j < 6 ; j++)
  {
    for (int i = 0; i < 6 ; i++)
    {
      if (buffer_help[i][1] == act_number)
      {
        if (missing_number < act_number)
        {
          buffer_help[i][1] = missing_number;
        }
        is_this_number_in_buffer = true;
        break;
      }
    }
    if (is_this_number_in_buffer = true)
    {
      missing_number++;
    }
    else
    {
      missing_number = act_number;
    }    
    act_number++;
    is_this_number_in_buffer = false;
  }
  
} 



bool clean_from_buffer(int expected_seq_number, bool * is_fin)
{
  bool is_in_buffer = false;
  for (int i = 0; i < 6; i++)
  {
    if (expected_seq_number == convert_byte_to_int(buffer_help[i], 2, 2))
    {
      *is_fin = (buffer_help[i][5] == 1) ? true: false;
      for (int j = 0; j < 98; j++)
      {
        buffer_temp_msg_static[i][j] = 0;
        if (j < 6)
        {
          buffer_help[i][j] = 0;
        }
      }
      sort_help_buffer();      
      is_in_buffer = true;
      break;
    }
  }

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis buffer table: ");
  for (int i = 0; i < 6; i++)
  {
    for (int j = 0; j < 20; j++)
    {
      Serial.print(buffer_temp_msg_static[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Help Buffer table: ");
  for (int i = 0; i < 6; i++)
  {
    for (int j = 0; j < 6; j++)
    {
      Serial.print(buffer_help[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }
  
  return is_in_buffer;
}


void convert_array_of_bytes_to_array(uint8_t output_data[], byte output_data_size, byte input_data[], byte start_index, byte input_data_size) //get array from MSG array to arduino
{
  if (output_data_size >= (input_data_size - start_index))
  {
    int j = start_index;
    for (int i = 0; i <  input_data_size; i++)
    {
      output_data[i] = input_data[j];
      j++;
    }
  }
  else
    Serial.println("Output size must be at least size of Input!");
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
    convert_number_to_array_on_position(data_array, i, 1, input_data[j]);
    j++;
  }
}



void sensors_and_actuators_init()
{
  Serial.println("start_sens");
  rfid_enable_eth_disable();
  SPI.begin(); // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522
  rfid_disable_eth_enable();
  Serial.println("end_sens");
}



void change_light_state(byte state)
{
  /*Serial.println("State come!");
  Serial.println(state);
  Serial.println("");
  if (state)
    digitalWrite(Light, HIGH);
  else
    digitalWrite(Light, LOW);*/
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



int create_packet(byte * packet_to_ret, byte * payload, int size_of_payload, bool is_crypted, int type, int seq_number)
{
  int size_of_whole_packet = 0;
  for (int i = 0; i < 98; i++)
  {
    packet_to_ret[i] = 0;
  }
  
  if (is_crypted) //tu niekde to crashuje
  {
    number_of_16_u_arrays = number_of_words_is(size_of_payload);
    
    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      for (int j = 0; j < 16; j++)
      {
        input_parts_of_packet_static[i][j] = 0;
        output_parts_of_packet_static[i][j] = 0;
      }
    }
    
    convert_number_to_array_on_position(packet_to_ret, 0, 2, type);
    convert_number_to_array_on_position(packet_to_ret, 2, 2, (long) seq_number);
    convert_array_to_array_on_position(packet_to_ret, 4, size_of_payload, payload); //set public key into msg
    
    int index = 0;
    int stop_index = 16;
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      for (; index < stop_index; index++)
      {
        if (index < (size_of_payload + 4))
        {
          input_parts_of_packet_static[i][index - (i * 16)] = packet_to_ret[index];
        }
      }
      stop_index += 16;
    }

    /*Serial.println("Not ciphered MSG in inputs arrays: ");
    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      Serial.print("Pole ");
      Serial.print(i);
      Serial.print(" is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(input_parts_of_packet_static[i][j]);
        Serial.print(", ");
      }
    }
    Serial.println("");
    Serial.println("");*/
    
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      speck.encryptBlock(&output_parts_of_packet_static[i][0], &input_parts_of_packet_static[i][0]);
    }

    /*Serial.println("Ciphered MSG in onputs arrays: ");
    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      Serial.print("Pole ");
      Serial.print(i);
      Serial.print(" is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(output_parts_of_packet_static[i][j]);
        Serial.print(", ");
      }
    }
    Serial.println("");
    Serial.println("");*/
    
    index = 0;
    stop_index = 16;
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      for (; index < stop_index; index++)
      {
        packet_to_ret[index] = output_parts_of_packet_static[i][index - (i * 16)];
      }
      stop_index += 16;
    }
    
    for (int i = 0; i < (number_of_16_u_arrays * 16); i++)
    {
      packet_to_checksum_static[i] = (uint16_t) packet_to_ret[i];
    }
    Serial.println("In create packet: 20");
    uint16_t checksum = sum_calc((number_of_16_u_arrays * 16), packet_to_checksum_static);
    Serial.println("In create packet: 22"); 
    convert_number_to_array_on_position(packet_to_ret, (number_of_16_u_arrays * 16), 2, (long) checksum); //set checksum into msg
    Serial.println("In create packet: 23");
    size_of_whole_packet = (16 * number_of_16_u_arrays) + 2;
    Serial.println("In create packet: 24");
  }
  else
  {    
    convert_number_to_array_on_position(packet_to_ret, 0, 2, type);
    convert_number_to_array_on_position(packet_to_ret, 2, 2, (long) seq_number);
    convert_array_to_array_on_position(packet_to_ret, 4, size_of_payload, payload); //set public key into msg
    for (int i = 0; i < (size_of_payload + 4); i++)
    {
      packet_to_checksum_static[i] = (uint16_t) packet_to_ret[i];
    }
    uint16_t checksum = sum_calc((size_of_payload + 4), packet_to_checksum_static);   
    convert_number_to_array_on_position(packet_to_ret, (size_of_payload + 4), 2, (long) checksum); //set checksum into msg
    size_of_whole_packet = (size_of_payload + 6);
  }
  return size_of_whole_packet;
}



void reg_and_auth()
{
  state_of_device = 0;
  register_completed = false;
  flag_of_success_reg_auth = true;
  while (flag_of_success_reg_auth)
  {
    switch(state_of_device)
      {
       case 0 : //send register msg
       {
          if (generate_dfh)
          {
            Serial.println("RLY generating keys!");
            Curve25519::dh1(public_key_of_arduino, private_key_of_arduino);
            sequence_number_generator();
          }
          else
          {
            Serial.println("FAKE generating keys!");
            for (int i = 0; i < 32; i++)
            {
              public_key_of_arduino[i] = fake_public_key_of_arduino[i];
              private_key_of_arduino[i] = fake_private_key[i];
            }
            act_seq_number = 1; // for test
            seq_number = act_seq_number;
            expected_seq_number = seq_number + 1;
          }
          Serial.println("");
          Serial.print("S0 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
          Serial.print(act_seq_number);
          Serial.print(seq_number);
          Serial.print(expected_seq_number);
          Serial.println("");
          
          size_of_packet = create_packet(temp_msg_static, public_key_of_arduino, sizeof(public_key_of_arduino), false, 0, seq_number);
          send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet);
          state_of_device++;
          break;
       }
       case 1 : //wait for public key from server
       {
          Serial.println("STATE 1");

          Serial.println("");
          Serial.print("S1 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
          Serial.print(act_seq_number);
          Serial.print(seq_number);
          Serial.print(expected_seq_number);
          Serial.println("");
          
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
                  Curve25519::dh2(public_key_of_server_or_ssecret_static, private_key_of_arduino);

                  Serial.print("Shared secret is: ");
                  for (int i = 0; i < 32; i++)
                  {
                    Serial.print(public_key_of_server_or_ssecret_static[i]);
                    Serial.print(", ");
                  }
                  Serial.println("");
                  Serial.println("");
                  
                  state_of_device++;
                  cancel_flag = 1;
                  have_gateway_pub_key = false;
                  speck.setKey(public_key_of_server_or_ssecret_static, 32); //with calculated cipher via DFH and set Speck key
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
       case 2 : //send ACK to reg response
       {
          Serial.println("STATE 2");
          sequence_number_generator();
          
          Serial.println("");
          Serial.print("S2 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
          Serial.print(act_seq_number);
          Serial.print(seq_number);
          Serial.print(expected_seq_number);
          Serial.println("");
          
          size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
          //send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet);// - The Real One
          state_of_device++;
          break;
       }
       case 3 : //wait for SALT - auth packet - SEQ
       {
          Serial.println("STATE 3");

          Serial.println("");
          Serial.print("S3 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
          Serial.print(act_seq_number);
          Serial.print(seq_number);
          Serial.print(expected_seq_number);
          Serial.println("");
          
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
            BLAKE2s blake;
            blake.reset(public_key_of_server_or_ssecret_static, sizeof(public_key_of_server_or_ssecret_static), 32);
            blake.update(salted_code, sizeof(salted_code));
            uint8_t hashed_auth_code[32];
            blake.finalize(hashed_auth_code, 32);
            
            Serial.print("HASH after Blake2s: ");
            for (int i = 0; i < 32; i++)
            {
              Serial.print(hashed_auth_code[i]);
              Serial.print(", ");
            }
            Serial.println("");
            Serial.println("");

            sequence_number_generator();

            Serial.println("");
            Serial.print("S4 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
            Serial.print(act_seq_number);
            Serial.print(seq_number);
            Serial.print(expected_seq_number);
            Serial.println("");

            Serial.print("1");
            size_of_packet = create_packet(temp_msg_static, hashed_auth_code, sizeof(hashed_auth_code), true, 5, seq_number);
            Serial.print("2");
            //send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            Serial.print("4");
            send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet); //- The Real One
            state_of_device++;
            Serial.print("5");
            break;
          }
       case 5 : //wait for acknoladge / notack
          {
            Serial.println("STATE 5");

            Serial.println("");
            Serial.print("S5 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
            Serial.print(act_seq_number);
            Serial.print(seq_number);
            Serial.print(expected_seq_number);
            Serial.println("");
            
            //seq number from packet must == seq_number;
            uint8_t wait_times = 0;
            uint8_t cancel_flag = 0;
            while (!cancel_flag) // listening UDP register_response packets
            {
              packetSize = udp.parsePacket();
              if (packetSize) // if UDP packets come
              {
                Serial.println("Come packet ack/nack");
                get_packet_to_buffer(true);
                int parse_permition = identify_packet();
                parse_packet((byte) parse_permition);
                if (come_ack)
                {
                  cancel_flag = 1;
                  come_ack = false;
                  state_of_device++;
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
       case 6 : //have to send data MSG about devices I have
          {
            Serial.println("STATE 6");

            sequence_number_generator();

            Serial.println("");
            Serial.print("S6 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
            Serial.print(act_seq_number);
            Serial.print(seq_number);
            Serial.print(expected_seq_number);
            Serial.println("");
            
            byte array_of_devices[92];
            int type_of_device_1 = 6;
            int size_of_array = 3 + 2; //3 for each device + 2 for item "0"
            
            for (int i = 0; i < 92; i++)
            {
              array_of_devices[i] = 0;
            }
            convert_number_to_array_on_position(array_of_devices, 2, 2, 1);
            convert_number_to_array_on_position(array_of_devices, 4, 1, type_of_device_1);
            Serial.println("msg about devices, not ciphered: ");
            for (int i = 0; i < 30; i++) // right is to 92 - but not needed for test (30 is good)
            {
              Serial.print(array_of_devices[i]);
              Serial.print(", ");
            }
            
            size_of_packet = create_packet(temp_msg_static, array_of_devices, size_of_array, true, (size_of_array + 4), seq_number);
            //send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet); //- The Real One
            state_of_device++;
            break;
          }
       case 7 : //wait for ack/nack of getting mine devices
          {
            Serial.println("STATE 7");

            Serial.println("");
            Serial.print("S7 TEST SEQ NUMBERS, ACT, SEQ, EXP: ");
            Serial.print(act_seq_number);
            Serial.print(seq_number);
            Serial.print(expected_seq_number);
            Serial.println("");
            
            //seq number from packet must == seq_number;
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
                  flag_of_success_reg_auth = false;
                  come_ack = false;
                  state_of_device++;
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
  int packet_size_shorted = packetSize - 2;
  
  for (int i = 0; i < (packet_size_shorted); i++)
  {
    packet_to_checksum_static[i] = (uint16_t) raw_packet_static[i];
  }
  
  uint16_t calc_checksum = sum_calc(packet_size_shorted, packet_to_checksum_static);
  int get_checksum = convert_byte_to_int(raw_packet_static, packet_size_shorted, 2);
    
  if (get_checksum == (int) calc_checksum)
  {
    Serial.println("Checksum PASS");
    return 1;
  }
  Serial.println("Checksum NOT PASS");
  return 0;
}



void set_command()
{
  Serial.print("Number of CMDS: ");
  int number_of_cmds = convert_byte_to_int(packet_buffer, 4, 1);
  Serial.print(number_of_cmds);
  Serial.println("");

  seq_number++;
  size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
  send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet); //for REAL ONE
  //send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);

  int offset = 0;
  for (int i = 0; i < number_of_cmds; i++)
  {
    int item = convert_byte_to_int(packet_buffer, (5 + offset), 2);
    if ((item > 0) && (item < 2)) // HERE SET CONSTRAINS THAT DEVICE ESP8266 HAVE!
    {
    Serial.println("Pushujem do sheduling table!");
    push_cmd_to_buffer(convert_byte_to_int(packet_buffer, (5 + offset), 2), convert_byte_to_int(packet_buffer, (7 + offset), 2), packet_buffer[9 + offset], convert_byte_to_int(packet_buffer, (10 + offset), 1)); //TO DO - podmienka, pushovat, len ak dane zariadenia mam!!!!!!!!!!!
    Serial.println("Dopushovane sheduling table!");
    }
    offset += 6;
  }
  do_command_from_sheduling_table(); // do CMD imidiately if has time 0 and so on
}



void push_cmd_to_buffer(int _item, int _value1, byte _value2, int _time)
{
  /*Serial.println("Vo funkcii pushovania!");
  Serial.println(_item);
  Serial.println(_value1);
  Serial.println(_value2);
  Serial.println(_time);
  Serial.println("");*/
  byte free_place_do_input_data = 100;
  
  
  for (int i = 0; i < 10; i++)
  {
    if (cmd_help[i][0] == 0) // found place for data
    {
      Serial.println("Find empty place in buffer for sheduling");
      free_place_do_input_data = i;
      cmd_help[free_place_do_input_data][2] = 1;
      break;
    }
  }
  
  if (free_place_do_input_data == 100)  //  not found place -> remove oldest
  {
    Serial.println("Not find empty place for shedulling - have to make some!");
    for (int i = 0; i < 10 ; i++)
    {
      if (cmd_help[i][1] == 10) // the oldest one
      {
        free_place_do_input_data = i; // attach removed place
        for (int j = 0; j < 7; j++)
        {
          sheduling_table[free_place_do_input_data][j] = 0; // clean of removed place
        }
        cmd_help[i][1] = 0;
      }
    }
  }
  for (int i = 0; i < 10 ; i++)
  {
    if (cmd_help[i][2] == 1) // uses at least one time
    {
      cmd_help[i][1]++;
    }
  }
  convert_number_to_array_on_position(sheduling_table[free_place_do_input_data], 0, 2, _item);
  convert_number_to_array_on_position(sheduling_table[free_place_do_input_data], 2, 2, (long) _value1);
  convert_number_to_array_on_position(sheduling_table[free_place_do_input_data], 4, 1, (long) _value2);
  convert_number_to_array_on_position(sheduling_table[free_place_do_input_data], 5, 2, (_time + minutes)); // time
  cmd_help[free_place_do_input_data][0] = 1;

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Sheduling table: ");
  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 7; j++)
    {
      Serial.print(sheduling_table[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Help CMD table: ");
  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 3; j++)
    {
      Serial.print(cmd_help[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }
  
  Serial.println("End funkcie pushovania!");
}



void do_command_from_sheduling_table()
{
  for (int i = 0; i < 10; i++)
  {
    if ((convert_byte_to_int(sheduling_table[i], 5, 2)) <= minutes)
    {
      switch(convert_byte_to_int(sheduling_table[i], 0, 2)) // must be actuator
      {
         case 1:
         {
            change_light_state((byte) get_float_from_cmd_format(convert_byte_to_int(sheduling_table[i], 2, 2), (byte) convert_byte_to_int(sheduling_table[i], 4, 1)));
            //change_light_state(convert_byte_to_int(sheduling_table[i], 2, 2)); // only for test
            break;
         }
         default:
         {
         }
      }
      for (int j = 0; j < 7; j++)
      {
        sheduling_table[i][j] = 0;
        if (j < 3)
        {
          cmd_help[i][j] = 0;
        }
      }
    }
  }
  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Sheduling table: ");
  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 7; j++)
    {
      Serial.print(sheduling_table[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }

  Serial.println("");
  Serial.println("");
  Serial.println("Vypis Help CMD table: ");
  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 3; j++)
    {
      Serial.print(cmd_help[i][j]);
      Serial.print(",");
    }
    Serial.println("");
  }
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
  Serial.println("Packet in get_packet_to_buffer");
  if (packetSize > 98)
  {
    Serial.println("MSG is too long!");
    return;
  }

  Serial.println("Come packet!");
  for (int i = 0; i < packetSize; i++)
  {
    Serial.print(packet_buffer[i]);
    Serial.print(", ");
  }
  Serial.println("");
  Serial.println("End of come packet!");
  
  for (int i = 0; i < packetSize; i++)
  {
    raw_packet_static[i] = packet_buffer[i];
  }
  
  if (need_decipher)
  {
    number_of_16_u_arrays = number_of_words_is(packetSize - 6);

    for (int i = 0; i < number_of_16_u_arrays; i++) //fill input + output by zeros
    {
      for (int j = 0; j < 16; j++)
      {
        input_parts_of_packet_static[i][j] = 0;
        output_parts_of_packet_static[i][j] = 0;
      }
    }
    
    if ((packetSize % 16 == 2) && (packetSize >= 18))
    {
      int index = 0;
      int stop_index = 16;
      for (int i = 0; i < number_of_16_u_arrays; i++)
      {
        for (; index < stop_index; index++)
        {
          if (index < (packetSize - 2))
          {
            input_parts_of_packet_static[i][index - (i * 16)] = packet_buffer[index];
          }
        }
        stop_index += 16;
      }
    /*Serial.println("Packet RDY for decipher is: (COME wthout checksum), only first part 16");
    for (int i = 0; i < 16; i++)
    {
      Serial.print(input_parts_of_packet_static[0][i]);
      Serial.print(", ");
    }*/


    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      speck.decryptBlock(&output_parts_of_packet_static[i][0], &input_parts_of_packet_static[i][0]);
    }
    
    index = 0;
    stop_index = 16;
    
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      for (; index < stop_index; index++)
      {
        packet_buffer[index] = output_parts_of_packet_static[i][index - (i * 16)];
      }
      stop_index += 16;
    }
    
    }
    else
     Serial.println("Part of packet is lost, Can not decipher!");
  }
  Serial.println("Packet in get_packet_to_buffer OUT");
}



int parse_packet(byte type_of_packet_to_parse) // 0 - for all
{
  Serial.println("In parse packet");
  print_general_info();
  if ((checksum_check()) && (packetSize <= 98))
  {
    int parse_permition = identify_packet();
    if ((type_of_packet_to_parse == 0) || (type_of_packet_to_parse == parse_permition))
    {    
      switch(parse_permition)
      {
       case 1 :
       {
        Serial.println("Parse 1");
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if (seq_number == expected_seq_number)
            {
              Serial.println("start get pub key of server");
              convert_array_of_bytes_to_array(public_key_of_server_or_ssecret_static, sizeof(public_key_of_server_or_ssecret_static), packet_buffer, 4, 32);
              have_gateway_pub_key = true;
              Serial.println("end get pub key of server");
            }
          }
          else  //in normal mode SEND NACK CIPHERED
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          }
          break;
       }
       case 2 : //acknowledgement_func();
       {
        Serial.println("Parse 2");
          if (!register_completed) //register mode
          {
            Serial.println("Som tu v ACK");
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if (seq_number == expected_seq_number)
            {
              Serial.println("Prislo dobre seq number");
              come_ack = true;
            }
            else
            {
              Serial.println("Prislo mi nespravne seq number");
            }
          }
          else  //in normal mode DO ST - WHEN I SEND DATA... I HAVE TO WAIT FOR ACK - TO DO;;;; When I send FIN - I WAIT TO SHUT DOWN - HAVE TO WAIT ACK        
          {
            bool come_fin_ack = false;
            if (clean_from_buffer(convert_byte_to_int(packet_buffer, 2, 2), &come_fin_ack))
            {
              Serial.println("Packet was deleted from buffer due to coming Right ACK");
              if (come_fin_ack)
              {
                come_fin_ack = false;
                stop_function();
              }
            }
          }          
          break;
       }
       case 3 : //not_acknowledgement_func();
       {
        Serial.println("Parse 3");
          if (!register_completed) //register mode
          {
            Serial.println("Som tu v NACK");
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if (seq_number == expected_seq_number)
            {
              Serial.println("Prislo dobre seq number");
              come_nack = true;
            }
            else
            {
              Serial.println("Prislo mi nespravne seq number");
            }
          }
          else  //in normal mode DO ST;;; When I send FIN - I WAIT TO SHUT DOWN - IF SERVER SEND ME NACK I INTERRUPT STOPPING
          {
            bool come_fin_nack = false;
            if (clean_from_buffer(convert_byte_to_int(packet_buffer, 2, 2), &come_fin_nack))
            {
              Serial.println("Packet was deleted from buffer due to coming Right NACK and stopping is interupted");
              come_fin_nack = false; // STOPPING rejected
            }
          }
          break;
       }
       case 4 : //authentication_func();
       {
        Serial.println("Parse 4");
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            /*Serial.println("Expected seq is: ");
            Serial.println(expected_seq_number);
            Serial.println("Seq number come is: ");
            Serial.println(seq_number);*/            
            if (seq_number == expected_seq_number)
            {
              //Serial.println("Come packet with right SEQ number!");
              //Serial.print("Salt come: ");
              for (int i = 0; i < 8; i++)
              {
                salt_from_server[i] = packet_buffer[i + 4];
                //Serial.print(salt_from_server[i]);
                //Serial.print(", ");
              }
              //Serial.println("");
              //Serial.println("");
              
              /*Serial.print("Auth CODE of Arduino is: ");
              for (int i = 0; i < 8; i++)
              {
                Serial.print(auth_code[i]);
                Serial.print(", ");
              }
              Serial.println("");
              Serial.println("");*/
              
              //Serial.print("Get SEQ number: ");
              //Serial.print(seq_number);
              //Serial.println("");
              //Serial.println("");
  
              //Serial.print("Xored is: ");
              for (int i = 0; i < 8; i++)
              {
                salted_code[i] = (auth_code[i] ^ salt_from_server[i]);
                //Serial.print(salted_code[i]);
                //Serial.print(", ");
              }
              //Serial.println("");
              //Serial.println("");
              have_salt = true;
            }
            else
            {
              Serial.println("Prislo mi nespravne seq number");
            }
          }
          else
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 5 : //mistake
       {
          Serial.println("Parse 5");
          if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          }
          else  //SEND NACK NOT CIPHERED
          {
            seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
            size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          }
          break;
       }
       case 6 : //COMMAND
       {
        Serial.println("Parse 6");
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number = convert_byte_to_int(packet_buffer, 2, 2);
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
          }
          else
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            set_command();
          }
          break;
       }
       case 7 : //STATUS
       {
        Serial.println("Parse 7");
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number = convert_byte_to_int(packet_buffer, 2, 2);
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
         }
         else //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet);
         }
         break;
       }
       case 8 : //FINISH
       {
        Serial.println("Parse 8");
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1;//In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            }
         }
         else //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER;;; STOP DEVICE
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet);          
            stop_function();
         }
         break;
       }
       default :  //Come DATA, not acceptable state
       {
          Serial.println("Parse default");
          if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
          {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          }
          else  //SEND NACK NOT CIPHERED
          {
            seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
            size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
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
    Serial.println("Wrong checksum or packet size > 98");
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
    ss_modes();
    rfid_disable_eth_enable();
    Ethernet.begin(mac, ip_arduino);
    udp.begin(localPort); // listen on port
    Serial.println("UDP listen");
    shedulling_table_init();
    buffer_init();
  
    sensors_and_actuators_init();  // initial of modules - se0nsors, actuators
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
  do_periodic_func();
  delay(5000);
  Serial.println("Koniec cakania");
  timer();
  
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
  }
}
//----------End of CODE----------
