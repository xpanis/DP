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
#define debug true  //true if debging.... false if correct program
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
int act_seq_number = 0;
int seq_number = 0;
int packetSize = 0;
int remote_port;
byte packet_buffer[UDP_TX_PACKET_MAX_SIZE]; //buffer to hold incoming packet
byte my_array[10]={-1,0,1,150,254,255,256,257,350,720};
byte ack_msg[6]={0,2,0,0,10,10};
uint8_t state_of_device = 0;
//byte *raw_packet;
byte raw_packet_static[98];
//byte *temp_msg;
byte temp_msg_static[98];
byte buffer_temp_msg_static[6][98];
byte buffer_help[6][6];
byte sheduling_table[10][7];
byte cmd_help[10][3];
//byte *temp_msg_to_cipher;
bool flag_of_success_reg_auth = true;
bool have_gateway_pub_key = false;
bool have_salt = false;
bool come_ack = false;
bool come_nack = false;
uint8_t number_of_16_u_arrays = 0;
uint16_t packet_to_checksum_static[96];
int size_of_packet = 0;
bool register_completed = false;
int time_to_send_buffer = 0;
//----------End of network settings----------


unsigned int seconds = 0;
unsigned int minutes = 0;
unsigned long timeNow = 0;
unsigned long timeLast = 0;
unsigned int last_minute = 0;
bool flag_of_random = true;


//----------Start of prepared msg----------
char reply_err_msg[] = "err msg, not identify type of msg";       // err msg
uint8_t input_parts_of_packet_static[6][16];
uint8_t output_parts_of_packet_static[6][16];
//----------End of prepared msg----------



//----------Start of cypher and shared secret----------
uint8_t auth_code[8] = {23, 138, 57, 62, 241, 37, 85, 11};  //special code for each device
uint8_t salt_from_server[8];
uint8_t salted_code[8];
uint8_t public_key_of_arduino[32];
uint8_t private_key_of_arduino[32];
//uint8_t * public_key_of_server_or_ssecret;
uint8_t public_key_of_server_or_ssecret_static[32];
uint8_t key_for_blake[32];
Speck speck;

uint8_t fake_public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t fake_private_key[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};
uint8_t fake_public_key_of_server[32] = {174, 243, 69, 129, 50, 14, 32, 63, 61, 38, 104, 233, 157, 59, 18, 146, 231, 38, 134, 104, 218, 18, 237, 151, 178, 213, 104, 139, 155, 21, 222, 119}; //just for test withou auth phase
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
void set_command();
int checksum_check();
int convert_byte_to_int(byte data[], byte start_index, byte data_size);
void alocate_msg_mem(byte **mem, uint8_t size_of_mem);
void convert_number_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t number_size, long number);
void convert_array_to_array_on_position(byte * data_array, uint8_t start_index, uint8_t input_data_size, byte * input_data);
void convert_array_of_bytes_to_array(uint8_t output_data[], byte output_data_size, byte input_data[], byte start_index, byte input_data_size);
void get_packet_to_buffer(bool need_decipher);
uint16_t sum_calc(uint16_t lenght, uint16_t * input);
int create_packet(byte * packet_to_ret, byte * payload, int size_of_payload, bool is_crypted, int type, int seq_number);
int number_of_words_is(int size_of_payload);
void stop_function();
void sort_help_buffer();
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


void do_periodic_func()
{
  //measere value from sensor and if is right time, send it as Data packet
  //or extra functionality
  //for test hard DATA:
  
  //sequence_number_generator();  -for real ONE
  seq_number = 100;
  expected_seq_number = seq_number + 1;
  byte data_to_send[8];
  byte item1 = 1; //temperature sensor
  byte item2 = 2; //preassure
  float temp_is = -11.21;
  float press_is = 350.06;
  
  byte rest_of_temp = 0;
  long temp = 0;
  byte rest_of_pressure = 0;
  long pressure = 0;
  int size_of_msg = sizeof(data_to_send) + 4;

  prepare_number_to_data_msg(temp_is, &rest_of_temp, &temp);
  prepare_number_to_data_msg(press_is, &rest_of_pressure, &pressure);
  
  convert_number_to_array_on_position(data_to_send, 0, 1, (long) item1);
  convert_number_to_array_on_position(data_to_send, 1, 2, temp);
  convert_number_to_array_on_position(data_to_send, 3, 1, rest_of_temp);

  convert_number_to_array_on_position(data_to_send, 4, 1, (long) item2);
  convert_number_to_array_on_position(data_to_send, 5, 2, pressure);
  convert_number_to_array_on_position(data_to_send, 7, 1, rest_of_pressure);
  
  size_of_packet = create_packet(temp_msg_static, data_to_send, sizeof(data_to_send), true, size_of_msg, seq_number);
  send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
  push_to_buffer(temp_msg_static, size_of_packet, expected_seq_number, false);
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
  for (int i = 0; i < 6 ; i++)
  {
    if (buffer_help[i][0] != 0)
    {
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




void push_to_buffer(byte input_data[], byte size_of_input_data, int seq_number, bool is_fin) //only DATA + FIN!!!!!!!!!!!!!!!
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
          //missing_number = act_number;
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
  Serial.println("In clean from buffer, seq number come");
  Serial.println(expected_seq_number);
  bool is_in_buffer = false;
  for (int i = 0; i < 6; i++)
  {
    if (expected_seq_number == convert_byte_to_int(buffer_help[i], 2, 2))
    {
      Serial.println("Deleting");
      *is_fin = (buffer_help[i][5] == 1) ? true: false;
      //clean from buffer
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



/*void alocate_msg_mem(byte **mem, uint8_t size_of_mem)
{
  *mem = NULL;
  *mem = (byte *) malloc(size_of_mem * sizeof(byte));

 if(*mem == NULL)
  {
      free(*mem);
      Serial.println("Erro of allocation!");
  }
}*/



void sensors_and_actuators_init()
{
  pinMode(Light, OUTPUT);
}



void change_light_state(byte state)
{
  Serial.println("State come!");
  Serial.println(state);
  Serial.println("");
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

    Serial.println("In input after fill is: ");
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
    Serial.println("");
    
    //speck.setKey(public_key_of_server_or_ssecret, 32); //with calculated cipher via DFH and set Speck key
    
    Serial.println("I: ");
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      Serial.print(i);
      Serial.print(", ");
      Serial.println("");
      speck.encryptBlock(&output_parts_of_packet_static[i][0], &input_parts_of_packet_static[i][0]);  //CRASHER HERE in i = 2; when come AUTH
      Serial.print("Ciphered is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(output_parts_of_packet_static[i][j]);
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
        packet_to_ret[index] = output_parts_of_packet_static[i][index - (i * 16)];
      }
      stop_index += 16;
    }
    Serial.println("In create packet: 15");
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
          
          size_of_packet = create_packet(temp_msg_static, public_key_of_arduino, sizeof(public_key_of_arduino), false, 0, seq_number);
          send_udp_msg(ip_pc, port_pc, temp_msg_static, size_of_packet);
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
          
          
          size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
          send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
          //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet); - The Real One
          state_of_device++;
          break;
       }
       case 3 : //wait for SALT - auth packet - SEQ
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

            sequence_number_generator();

            Serial.print("1");
            size_of_packet = create_packet(temp_msg_static, hashed_auth_code, sizeof(hashed_auth_code), true, 5, seq_number);
            Serial.print("2");
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            Serial.print("4");
            //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet); - The Real One
            state_of_device++;
            Serial.print("5");
            break;
          }
       case 5 : //wait for acknoladge / notack
          {
            Serial.println("STATE 5");
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
            
            byte array_of_devices[92];
            int type_of_device_1 = 6;
            int size_of_array = 3 + 2; //3 for each device + 2 for item "0"
            
            for (int i = 0; i < 92; i++)
            {
              array_of_devices[i] = 0;
            }
            convert_number_to_array_on_position(array_of_devices, 2, 2, 1);
            convert_number_to_array_on_position(array_of_devices, 4, 1, type_of_device_1);
            Serial.println("msg about devices: ");
            for (int i = 0; i < 92; i++)
            {
              Serial.print(array_of_devices[i]);
              Serial.print(", ");
            }
            
            size_of_packet = create_packet(temp_msg_static, array_of_devices, size_of_array, true, (size_of_array + 4), seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet); - The Real One
            state_of_device++;
            break;
          }
       case 7 : //wait for ack/nack of getting mine devices
          {
            Serial.println("STATE 7");
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
  //send_udp_msg(ip_pc, port_pc, temp_msg, size_of_packet);
  send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
  //send_udp_msg(remote_ip, remote_port, ack_msg, (sizeof(ack_msg))); // send ACK

  int offset = 0;
  for (int i = 0; i < number_of_cmds; i++)
  {
    Serial.println("Pushujem do sheduling table!");
    //set command into sheduling table
    push_cmd_to_buffer(convert_byte_to_int(packet_buffer, (5 + offset), 2), convert_byte_to_int(packet_buffer, (7 + offset), 2), packet_buffer[9 + offset], convert_byte_to_int(packet_buffer, (10 + offset), 2)); //TO DO - podmienka, pushovat, len ak dane zariadenia mam!!!!!!!!!!!
    Serial.println("Dopushovane sheduling table!");
    offset += 7;
  }
}



void push_cmd_to_buffer(int _item, int _value1, byte _value2, int _time) //needed function for get float from 3 bytes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
{
  byte free_place_do_input_data = 100;
  
  Serial.println("Vo funkcii pushovania!");
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
      //do CMD with index I; TO DO
      switch(convert_byte_to_int(sheduling_table[i], 0, 2)) // must be actuator
      {
         case 1:
         {
            //change_light_state(convert_byte_to_int(sheduling_table[i], 2, 3)); // change state of lamp -- WARNING - have to do parse special format of number!!!!
            change_light_state(convert_byte_to_int(sheduling_table[i], 2, 2)); // only for test
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
  for (int i = 0; i < packetSize; i++)
  {
    raw_packet_static[i] = packet_buffer[i];
  }
  Serial.println("here 1");
  if (need_decipher)
  {
    number_of_16_u_arrays = number_of_words_is(packetSize - 6);
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
    Serial.println("Packet RDY for decipher is: (COME wthout checksum)");
    for (int i = 0; i < 16; i++)
    {
      Serial.print(input_parts_of_packet_static[0][i]);
      Serial.print(", ");
    }


    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      speck.decryptBlock(&output_parts_of_packet_static[i][0], &input_parts_of_packet_static[i][0]);
      Serial.print("Deciphered is: ");
      for (int j = 0; j < 16; j++)
      {
        Serial.print(output_parts_of_packet_static[i][j]);
        Serial.print(", ");
      }
      Serial.print(" Decrypt OK! ");
      Serial.println("");
    }
    Serial.println("");
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
  if (checksum_check())
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
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            //in normal mode SEND NACK CIPHERED
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
          }
          else
          {
            //in normal mode DO ST - WHEN I SEND DATA... I HAVE TO WAIT FOR ACK - TO DO
            //When I send FIN - I WAIT TO SHUT DOWN - HAVE TO WAIT ACK
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
          }
          else
          {
            //in normal mode DO ST
            //When I send FIN - I WAIT TO SHUT DOWN - IF SERVER SEND ME NACK I INTERRUPT STOPPING
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
            Serial.println("Expected seq is: ");
            Serial.println(expected_seq_number);
            Serial.println("Seq number come is: ");
            Serial.println(seq_number);
            
            if (seq_number == expected_seq_number)
            {
              Serial.println("Come packet with right SEQ number!");
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
          }
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 5 : //mistake
       {
        Serial.println("Parse 5");
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            seq_number = 1; //TO DO
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 6 : //COMMAND
       {
        Serial.println("Parse 6");
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            set_command(); //TO DO!!!!!!!!!!!!!!!!!!!!!!!!
          }
          break;
       }
       case 7 : //STATUS
       {
        Serial.println("Parse 7");
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
         }
         else
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);     
            //status_func();
            //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
         }
         break;
       }
       case 8 : //FINISH
       {
        Serial.println("Parse 8");
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
         }
         else
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);          
            stop_function();
           //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
           //STOP DEVICE
         }
         break;
       }
       default :  //DATA
       {
        Serial.println("Parse default");
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2)
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //in normal mode SEND NACK CIPHERED
            }
            else
            {
              seq_number = 1; //TO DO
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
              //SEND NACK NOT CIPHERED
            }
          }
          else
          {
            default_func();
            seq_number = 1; //TO DO
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_udp_msg(remote_ip, remote_port, temp_msg_static, size_of_packet);
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
  shedulling_table_init();
  buffer_init();

  sensors_and_actuators_init();  // initial of modules - sensors, actuators
  reg_and_auth(); // registration of whole device to gateway
  Serial.println("Koniec reg_and auth");
  }
  else  //test
  {
    connect_to_net_via_wifi();  // connet to network
 
    udp.begin(localPort); // listen on port
    Serial.println("UDP listen");
    shedulling_table_init();
    buffer_init();
  
    sensors_and_actuators_init();  // initial of modules - sensors, actuators

    for (int i = 0; i < 32; i++)
    {
      public_key_of_arduino[i] = fake_public_key_of_arduino[i];
      private_key_of_arduino[i] = fake_private_key[i];
      public_key_of_server_or_ssecret_static[i] = fake_public_key_of_server[i];
    }
    state_of_device = 8;
    register_completed = true;
    
    Curve25519::dh2(public_key_of_server_or_ssecret_static, private_key_of_arduino);
    Serial.print("Shared secret is: ");
    for (int i = 0; i < 32; i++)
    {
      Serial.print(public_key_of_server_or_ssecret_static[i]);
      Serial.print(", ");
    }
    Serial.println("");
    Serial.println("");
    
    speck.setKey(public_key_of_server_or_ssecret_static, 32);
    
    Serial.println("Koniec reg_and auth");
  }
}



void loop()
{
  if (!debug)
  {
  // start time for addition code e.g. call of funcion on relay, lamp, door lock
  Serial.println("Zaciatok cakania");
  do_periodic_func();
  delay(10000);
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
        // start time for addition code e.g. call of funcion on relay, lamp, door lock
      /*Serial.println("Zaciatok cakania");
      do_periodic_func();
      delay(10000);
      Serial.println("Koniec cakania");
      
      timer();
      
      // end time for addition code*/
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
    do_periodic_func();
    delay(5000);
  //test
  }
}
//----------End of CODE----------
