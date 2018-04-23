#include <Curve25519.h>
#include <BLAKE2s.h>
#include <Crypto.h>
#include <Speck.h>

uint8_t secret[32] = {16, 29, 211, 181, 107, 23, 26, 25, 8, 122, 106, 92, 17, 35, 223, 136, 149, 91, 46, 98, 186, 41, 148, 25, 139, 129, 156, 99, 37, 103, 49, 49};
uint8_t fake_public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t public_key_of_server[32] = {174, 243, 69, 129, 50, 14, 32, 63, 61, 38, 104, 233, 157, 59, 18, 146, 231, 38, 134, 104, 218, 18, 237, 151, 178, 213, 104, 139, 155, 21, 222, 119};
byte * test_array[5];// = {16, 29, 211, 181, 107};
uint8_t salt[2] = {7,32};
uint8_t hash[32];
uint8_t key[32];
uint8_t key_for_blake[32];
Speck speck;

int number_of_16_u_arrays = 0;
uint8_t ** input_parts_of_packet;
uint8_t ** output_parts_of_packet;
byte *temp_msg;
byte *temp_msg_to_cipher;
uint16_t * packet_to_checksum;

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
  int size_of_whole_packet = 0;
  *packet_to_ret = NULL;
  byte * msg;
  msg = *packet_to_ret;
  free(msg);
  
  if (is_crypted)
  {
    number_of_16_u_arrays = number_of_words_is(size_of_payload);
    free(temp_msg_to_cipher);
    free(input_parts_of_packet);
    free(output_parts_of_packet);
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
    
    free(temp_msg_to_cipher);
    speck.setKey(secret, 32); //with calculated cipher via DFH and set Speck key
    for (int i = 0; i < number_of_16_u_arrays; i++)
    {
      speck.encryptBlock(&output_parts_of_packet[i][0], &input_parts_of_packet[i][0]);
    }
    
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
    
    free(input_parts_of_packet);
    free(output_parts_of_packet);
    
    packet_to_checksum =  (uint16_t *) malloc((number_of_16_u_arrays * 16) * sizeof(uint16_t));
    for (int i = 0; i < (number_of_16_u_arrays * 16); i++)
    {
      packet_to_checksum[i] = (uint16_t) msg[i];
    }
    uint16_t checksum = sum_calc((number_of_16_u_arrays * 16), packet_to_checksum);
    free(packet_to_checksum);    
    convert_number_to_array_on_position(msg, (number_of_16_u_arrays * 16), 2, (long) checksum); //set checksum into msg
    size_of_whole_packet = (16 * number_of_16_u_arrays) + 2;
  }
  else
  {
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
    free(packet_to_checksum);    
    convert_number_to_array_on_position(msg, (size_of_payload + 4), 2, (long) checksum); //set checksum into msg
    size_of_whole_packet = (size_of_payload + 6);
  }
  return size_of_whole_packet;
}



void setup() {
  Serial.begin(9600); // serial start for help print to console

  
  free(temp_msg);
  int size_of_packet = create_packet(&temp_msg, public_key_of_server, sizeof(public_key_of_server), false, 1, 32);
  Serial.print("Packet is: ");
  for (int i = 0; i < size_of_packet; i++)
    {
      Serial.print(temp_msg[i]);
      Serial.print(", ");
    }
    
  Serial.println("");
  Serial.println("");
  
  free(temp_msg);
  size_of_packet = create_packet(&temp_msg, salt, sizeof(salt), true, 4, 57);
  Serial.print("Packet is: ");
  for (int i = 0; i < size_of_packet; i++)
    {
      Serial.print(temp_msg[i]);
      Serial.print(", ");
    }
}

void loop() {
}
