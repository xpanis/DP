//----------Start of libs----------
#include <Curve25519.h>
#include <Speck.h>
#include <BLAKE2s.h>
//----------End of libs----------



//----------Start of define----------
#define light1 6
#define light2 7
#define debug false  //true if debging.... false if correct program
#define generate_dfh false  //if false -> communicate with server via define keys
//----------End of define----------



//----------Start of network settings mine----------
int myTimeout = 250;  // milliseconds for readString
//----------End of network settings----------



//----------Start of Fields----------
byte packet_buffer[98]; //buffer to hold incoming packet
byte input_packet_buffer[102];
uint8_t input_parts_of_packet_static[6][16];
uint8_t output_parts_of_packet_static[6][16];
uint16_t packet_to_checksum_static[96];
byte raw_packet_static[98];
byte temp_msg_static[98];
byte temp_msg_static_bt[102];
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
int real_length = 0;
int packetSize = 0;
int size_of_packet = 0;
//----------End of Variables----------



//----------Start of Flags----------
bool is_next_zero = false;
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
uint8_t auth_code[8] = {94, 233, 245, 4, 194, 218, 83, 69};  //special code for each device
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
void sensors_and_actuators_init();
void shedulling_table_init();
void buffer_init();
void reg_and_auth();
//----------End of Init function declaration----------



//----------Start of function for sending data declaration----------
void send_bt_msg(byte msg[], byte size_of_msg);
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
void buffer_for_bt_init();
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
void change_light_state(byte state, byte device);
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
}


void timer()
{
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




void buffer_for_bt_init()
{
  for (int i = 0; i < 102; i++)
  {
    input_packet_buffer[i] = 0;
    if (i < 98)
    {
      packet_buffer[i] = 0;
    }
  }
}



void retransmission()
{
  for (int i = 0; i < 6 ; i++)
  {
    if (buffer_help[i][0] != 0)
    {
      send_bt_msg(&buffer_temp_msg_static[i][0], buffer_help[i][0]); //can be remote IP and PORT
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
  pinMode(light1, OUTPUT);
  pinMode(light2, OUTPUT);
}



void change_light_state(byte state, byte device)
{
  switch(device)
  {
     case 1 :
     {
      if (state)
      {
        digitalWrite(light1, HIGH);
      }
      else
      {
        digitalWrite(light1, LOW);
      }
      break;
     }
     case 2 :
     {
      if (state)
      {
        digitalWrite(light2, HIGH);
      }
      else
      {
        digitalWrite(light2, LOW);
      }
      break;
     }
  }
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
    
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      speck.encryptBlock(&output_parts_of_packet_static[i][0], &input_parts_of_packet_static[i][0]);
    }
    
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
    uint16_t checksum = sum_calc((number_of_16_u_arrays * 16), packet_to_checksum_static);
    convert_number_to_array_on_position(packet_to_ret, (number_of_16_u_arrays * 16), 2, (long) checksum); //set checksum into msg
    size_of_whole_packet = (16 * number_of_16_u_arrays) + 2;
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
            Curve25519::dh1(public_key_of_arduino, private_key_of_arduino);
            sequence_number_generator();
          }
          else
          {
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
          send_bt_msg(temp_msg_static, size_of_packet);
          state_of_device++;
          break;
       }
       case 1 : //wait for public key from server
       {          
          uint8_t wait_times = 0;
          uint8_t cancel_flag = 0;
          while (!cancel_flag) // listening UDP register_response packets
          {
            
            if (Serial.available())
            {
              Serial.readBytes(input_packet_buffer, 102);
              if ((input_packet_buffer[0] == 255) && (input_packet_buffer[1] == 255))
              {
                for (int i = 0; i < 98; i++)
                {
                  is_next_zero = (input_packet_buffer[i + 4] == 0)? true : false;
                  
                  if ((input_packet_buffer[i + 2] == 255) && (input_packet_buffer[i + 3] == 255) && is_next_zero)
                  {
                    break;
                  }
                  else
                  {
                    packet_buffer[i] = input_packet_buffer[i + 2];
                    real_length++;
                  }
                }
            
                packetSize = real_length;
                get_packet_to_buffer(false);
                parse_packet(1);

                if (have_gateway_pub_key)
                {
                  Curve25519::dh2(public_key_of_server_or_ssecret_static, private_key_of_arduino);                  
                  state_of_device++;
                  cancel_flag = 1;
                  have_gateway_pub_key = false;
                  speck.setKey(public_key_of_server_or_ssecret_static, 32); //with calculated cipher via DFH and set Speck key
                }
            
                for (int i = 0; i < 102; i++)
                {
                input_packet_buffer[i] = 0;
                }
                real_length = 0;
              }
            }
            else
            {
              if (wait_times < 10)  //wait 5 sec for public key of server, if not come set case 0
              {
                delay(2000);
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
          sequence_number_generator();          
          size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
          send_bt_msg(temp_msg_static, size_of_packet);
          state_of_device++;
          break;
       }
       case 3 : //wait for SALT - auth packet - SEQ
       {          
          uint8_t wait_times = 0;
          uint8_t cancel_flag = 0;
          while (!cancel_flag) // listening UDP register_response packets
          {
  
            if (Serial.available())
            {
              Serial.readBytes(input_packet_buffer, 102);
              if ((input_packet_buffer[0] == 255) && (input_packet_buffer[1] == 255))
              {
                for (int i = 0; i < 98; i++)
                {
                  is_next_zero = (input_packet_buffer[i + 4] == 0)? true : false;
                  
                  if ((input_packet_buffer[i + 2] == 255) && (input_packet_buffer[i + 3] == 255) && is_next_zero)
                  {
                    break;
                  }
                  else
                  {
                    packet_buffer[i] = input_packet_buffer[i + 2];
                    real_length++;
                  }
                }
            
                packetSize = real_length;
                get_packet_to_buffer(true);
                parse_packet(4);
                if (have_salt)
                {
                  state_of_device++;
                  cancel_flag = 1;
                  have_salt = false;
                }
            
                for (int i = 0; i < 102; i++)
                {
                input_packet_buffer[i] = 0;
                }
                real_length = 0;
              }
            }
            else
            {
              if (wait_times < 10)  //wait 5 sec for salt, if not come set case 0
              {
                delay(2000);
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
            BLAKE2s blake;
            blake.reset(public_key_of_server_or_ssecret_static, sizeof(public_key_of_server_or_ssecret_static), 32);
            blake.update(salted_code, sizeof(salted_code));
            uint8_t hashed_auth_code[32];
            blake.finalize(hashed_auth_code, 32);
            sequence_number_generator();
            size_of_packet = create_packet(temp_msg_static, hashed_auth_code, sizeof(hashed_auth_code), true, 5, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
            state_of_device++;
            break;
          }
       case 5 : //wait for acknoladge / notack
          {            
            //seq number from packet must == seq_number;
            uint8_t wait_times = 0;
            uint8_t cancel_flag = 0;
            while (!cancel_flag) // listening UDP register_response packets
            {

              if (Serial.available())
              {
                Serial.readBytes(input_packet_buffer, 102);
                if ((input_packet_buffer[0] == 255) && (input_packet_buffer[1] == 255))
                {
                  for (int i = 0; i < 98; i++)
                  {
                    is_next_zero = (input_packet_buffer[i + 4] == 0)? true : false;
                    
                    if ((input_packet_buffer[i + 2] == 255) && (input_packet_buffer[i + 3] == 255) && is_next_zero)
                    {
                      break;
                    }
                    else
                    {
                      packet_buffer[i] = input_packet_buffer[i + 2];
                      real_length++;
                    }
                  }
              
                  packetSize = real_length;
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
                  }
              
                  for (int i = 0; i < 102; i++)
                  {
                  input_packet_buffer[i] = 0;
                  }
                  real_length = 0;
                }
              }
              else
              {
                if (wait_times < 10)  //wait 5 sec for salt, if not come set case 0
                {
                  delay(2000);
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
            sequence_number_generator();
            
            byte array_of_devices[92];
            int type_of_device_1 = 6;
            int type_of_device_2 = 6;
            int size_of_array = (3 * 2) + 2; //3 for each device + 2 for item "0"
            
            for (int i = 0; i < 92; i++)
            {
              array_of_devices[i] = 0;
            }
            convert_number_to_array_on_position(array_of_devices, 2, 2, 1);
            convert_number_to_array_on_position(array_of_devices, 4, 1, type_of_device_1);

            convert_number_to_array_on_position(array_of_devices, 5, 2, 1);
            convert_number_to_array_on_position(array_of_devices, 7, 1, type_of_device_1);
            
            size_of_packet = create_packet(temp_msg_static, array_of_devices, size_of_array, true, (size_of_array + 4), seq_number);  //allert seq number
            send_bt_msg(temp_msg_static, size_of_packet);
            state_of_device++;
            break;
          }
       case 7 : //wait for ack/nack of getting mine devices
          {            
            //seq number from packet must == seq_number;
            uint8_t wait_times = 0;
            uint8_t cancel_flag = 0;
            while (!cancel_flag) // listening UDP register_response packets
            {
              if (Serial.available())
              {
                Serial.readBytes(input_packet_buffer, 102);
                if ((input_packet_buffer[0] == 255) && (input_packet_buffer[1] == 255))
                {
                  for (int i = 0; i < 98; i++)
                  {
                    is_next_zero = (input_packet_buffer[i + 4] == 0)? true : false;
                    
                    if ((input_packet_buffer[i + 2] == 255) && (input_packet_buffer[i + 3] == 255) && is_next_zero)
                    {
                      break;
                    }
                    else
                    {
                      packet_buffer[i] = input_packet_buffer[i + 2];
                      real_length++;
                    }
                  }
              
                  packetSize = real_length;
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
                  }
              
                  for (int i = 0; i < 102; i++)
                  {
                  input_packet_buffer[i] = 0;
                  }
                  real_length = 0;
                }
              }
              else
              {
                if (wait_times < 10)  //wait 5 sec for salt, if not come set case 0
                {
                  delay(2000);
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
    return 1;
  }
  return 0;
}



void set_command()
{
  int number_of_cmds = convert_byte_to_int(packet_buffer, 4, 1);
  seq_number++;
  size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
  send_bt_msg(temp_msg_static, size_of_packet);

  int offset = 0;
  for (int i = 0; i < number_of_cmds; i++)
  {
    int item = convert_byte_to_int(packet_buffer, (5 + offset), 2);
    
    if ((item > 0) && (item < 3)) // HERE SET CONSTRAINS THAT DEVICE ESP8266 HAVE!
    {
      push_cmd_to_buffer(convert_byte_to_int(packet_buffer, (5 + offset), 2), convert_byte_to_int(packet_buffer, (7 + offset), 2), packet_buffer[9 + offset], convert_byte_to_int(packet_buffer, (10 + offset), 1)); //TO DO - podmienka, pushovat, len aks dane zariadenia mam!!!!!!!!!!!
    }
    offset += 6;
  }
  do_command_from_sheduling_table(); // do CMD imidiately if has time 0 and so on
}



void push_cmd_to_buffer(int _item, int _value1, byte _value2, int _time)
{
  byte free_place_do_input_data = 100;
  
  
  for (int i = 0; i < 10; i++)
  {
    if (cmd_help[i][0] == 0) // found place for data
    {
      free_place_do_input_data = i;
      cmd_help[free_place_do_input_data][2] = 1;
      break;
    }
  }
  
  if (free_place_do_input_data == 100)  //  not found place -> remove oldest
  {
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
            change_light_state((byte) round(get_float_from_cmd_format(convert_byte_to_int(sheduling_table[i], 2, 2), (byte) convert_byte_to_int(sheduling_table[i], 4, 1))), 1);
            break;
         }
         case 2:
         {
            change_light_state((byte) round(get_float_from_cmd_format(convert_byte_to_int(sheduling_table[i], 2, 2), (byte) convert_byte_to_int(sheduling_table[i], 4, 1))), 2);
            break;
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
}



void print_general_info()
{
}



void get_packet_to_buffer(bool need_decipher)
{
  if (packetSize > 98)
  {
    return;
  }
  
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
  }
}



int parse_packet(byte type_of_packet_to_parse) // 0 - for all
{
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
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if (seq_number == expected_seq_number)
            {
              convert_array_of_bytes_to_array(public_key_of_server_or_ssecret_static, sizeof(public_key_of_server_or_ssecret_static), packet_buffer, 4, 32);
              have_gateway_pub_key = true;
            }
          }
          else  //in normal mode SEND NACK CIPHERED
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
          }
          break;
       }
       case 2 : //acknowledgement_func();
       {
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if ((seq_number == expected_seq_number) || true) //or with true only for test
            {
              come_ack = true;
            }
          }
          else  //in normal mode DO ST - WHEN I SEND DATA... I HAVE TO WAIT FOR ACK - TO DO;;;; When I send FIN - I WAIT TO SHUT DOWN - HAVE TO WAIT ACK        
          {
            bool come_fin_ack = false;
            if (clean_from_buffer(convert_byte_to_int(packet_buffer, 2, 2), &come_fin_ack))
            {
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
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            if (seq_number == expected_seq_number)
            {
              come_nack = true;
            }
          }
          else  //in normal mode DO ST;;; When I send FIN - I WAIT TO SHUT DOWN - IF SERVER SEND ME NACK I INTERRUPT STOPPING
          {
            bool come_fin_nack = false;
            if (clean_from_buffer(convert_byte_to_int(packet_buffer, 2, 2), &come_fin_nack))
            {
              come_fin_nack = false; // STOPPING rejected
            }
          }
          break;
       }
       case 4 : //authentication_func();
       {
          if (!register_completed) //register mode
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2); //get seq number        
            if (seq_number == expected_seq_number)
            {
              for (int i = 0; i < 8; i++)
              {
                salt_from_server[i] = packet_buffer[i + 4];
              }
              for (int i = 0; i < 8; i++)
              {
                salted_code[i] = (auth_code[i] ^ salt_from_server[i]);
              }
              have_salt = true;
            }
          }
          else
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
            //in normal mode SEND NACK CIPHERED
          }
          break;
       }
       case 5 : //mistake
       {
          if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
          {
            seq_number = convert_byte_to_int(packet_buffer, 2, 2);
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
          }
          else  //SEND NACK NOT CIPHERED
          {
            seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
            size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
          }
          break;
       }
       case 6 : //COMMAND
       {
          if (!register_completed) //register mode
          {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number = convert_byte_to_int(packet_buffer, 2, 2);
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
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
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number = convert_byte_to_int(packet_buffer, 2, 2);
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
            }
         }
         else //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
         }
         break;
       }
       case 8 : //FINISH
       {
         if (!register_completed) //register mode
         {
            if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
            {
              seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
              seq_number++;
              size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
            }
            else  //SEND NACK NOT CIPHERED
            {
              seq_number = 1;//In that time I can not read ciphered msg.. so seq number for sending NACK is default
              size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
              send_bt_msg(temp_msg_static, size_of_packet);
            }
         }
         else //SEND ACK CIPHERED WITH CORRECT SEQ NUMBER;;; STOP DEVICE
         {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 2, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);          
            stop_function();
         }
         break;
       }
       default :  //Come DATA, not acceptable state
       {
          if (state_of_device >= 2) //in normal mode SEND NACK CIPHERED
          {
            seq_number =  convert_byte_to_int(packet_buffer, 2, 2); //get seq number
            seq_number++;
            size_of_packet = create_packet(temp_msg_static, NULL, 0, true, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
          }
          else  //SEND NACK NOT CIPHERED
          {
            seq_number = 1; //In that time I can not read ciphered msg.. so seq number for sending NACK is default
            size_of_packet = create_packet(temp_msg_static, NULL, 0, false, 3, seq_number);
            send_bt_msg(temp_msg_static, size_of_packet);
          }
       }
      }
    }
  }
  else
  {
    return 0; //fail of parse packet
  }    
  return 1; //corect parse packet
}



void send_bt_msg(byte msg[], byte size_of_msg)
{
  for (int i = 0; i < 102; i++)
  {
    temp_msg_static_bt[i] = 0;
  }

  temp_msg_static_bt[0] = 255;
  temp_msg_static_bt[1] = 255;
  temp_msg_static_bt[size_of_msg + 2] = 255;
  temp_msg_static_bt[size_of_msg + 3] = 255;

  for (int i = 0; i < size_of_msg; i++)
  {
    temp_msg_static_bt[i + 2] = msg[i];
  }

  Serial.write(temp_msg_static_bt, (int) (size_of_msg + 4));
  delay(10);
}



void default_func() // print receivd msg and send error msg back
{
}



void stop_function()
{
  while(1)
  {
    delay(10000);
  }
}



void setup()
{
  Serial.begin(9600);
  //------------Serial.setTimeout(myTimeout);
  delay(100);

  if (!debug)
  {
  while (!Serial) {}
  shedulling_table_init();
  buffer_init();
  buffer_for_bt_init();
  
  sensors_and_actuators_init();  // initial of modules - sensors, actuators
  reg_and_auth(); // registration of whole device to gateway
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
  do_periodic_func();
  delay(5000);
  timer();
  // end time for addition code
    
    if (Serial.available())
    {
      Serial.readBytes(input_packet_buffer, 102);
      if ((input_packet_buffer[0] == 255) && (input_packet_buffer[1] == 255))
      {
          for (int i = 0; i < 98; i++)
          {
            is_next_zero = (input_packet_buffer[i + 4] == 0)? true : false;
            
            if ((input_packet_buffer[i + 2] == 255) && (input_packet_buffer[i + 3] == 255) && is_next_zero)
            {
              break;
            }
            else
            {
              packet_buffer[i] = input_packet_buffer[i + 2];
              real_length++;
            }
          }

          packetSize = real_length;
          get_packet_to_buffer(true);
          int parse_permition = identify_packet();
          parse_packet((byte) parse_permition);
  
          for (int i = 0; i < 102; i++)
          {
            input_packet_buffer[i] = 0;
          }
          real_length = 0;
      }
    }
  }
  else
  {
  }
}
//----------End of CODE----------
