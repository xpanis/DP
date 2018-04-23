#include <Curve25519.h>
#include <BLAKE2s.h>
#include <Crypto.h>
#include <Speck.h>
#include <stdlib.h>

uint8_t public_key_of_server[32] = {174, 243, 69, 129, 50, 14, 32, 63, 61, 38, 104, 233, 157, 59, 18, 146, 231, 38, 134, 104, 218, 18, 237, 151, 178, 213, 104, 139, 155, 21, 222, 119};
uint8_t private_key_of_server[32] = {216, 42, 26, 169, 32, 50, 138, 171, 206, 170, 83, 7, 104, 211, 88, 221, 49, 94, 112, 117, 211, 58, 160, 178, 193, 28, 36, 174, 72, 110, 96, 105};

uint8_t public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t private_key_of_arduino[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};

uint8_t secret_server[32];
uint8_t secret_arduino[32];

uint8_t auth_code_of_arduino[2] = {23, 138};
uint8_t salt[2] = {7,32};
uint8_t salted_code[2];
uint8_t hash[32];
uint8_t key[32];

uint8_t text[20] = "Toto je test Text";
uint8_t newtext[6];
uint8_t newtext_correct_size[16];
uint8_t cipher_text[6];
uint8_t cipher_text_correct_size[16];
uint8_t secret_cipher[32];
uint8_t * merged_without_checksum_8_correct_size_checksum;
uint16_t * merged_without_checksum_8_correct_size_checksum16;

Speck speck;

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

uint16_t * merge_packet(uint8_t * type_size, uint8_t * seq_number, uint8_t * payload, int size_of_payload)
{
  uint16_t * packet;
  packet = (uint16_t *) malloc((sizeof((uint16_t) size_of_payload) + (4 * sizeof(uint16_t))));
  
  packet[0] = type_size[0];
  packet[1] = type_size[1];
  packet[2] = seq_number[0];
  packet[3] = seq_number[1];
  int i;
  
  for (i = 4; i < (size_of_payload + 4); i++)
  {
    packet[i] = payload[i - 4];
  }
  return &packet[0];
}

uint16_t * create_packet(uint8_t * type_size, uint8_t * seq_number, uint8_t * payload, int size_of_payload)
{
  uint16_t * packet;
  packet = (uint16_t *) malloc((sizeof((uint16_t) size_of_payload) + (6 * sizeof(uint16_t))));
  
  packet[0] = type_size[0];
  packet[1] = type_size[1];
  packet[2] = seq_number[0];
  packet[3] = seq_number[1];
  int i;
  
  for (i = 4; i < (size_of_payload + 4); i++)
  {
    packet[i] = payload[i - 4];
  }

  uint8_t checksum_high = 0;
  uint8_t checksum_low = 0;
  uint16_t checksum = 0;

  packet[i] = checksum_high;
  i++;
  packet[i] = checksum_high;
  
  checksum = sum_calc(i - 1, packet);
  
  checksum_high = ((checksum & 0xFF00) >> 8);
  checksum_low = checksum & 0xFF;
  
  packet[i - 1] = checksum_high;
  packet[i] = checksum_low;

  Serial.println("Packet s checksumom: ");
  for (int j = 0; j < 20; j++)
  {
    Serial.print(packet[j]);
    Serial.print(", ");
  }
  Serial.println("END");
  return &packet[0];
}


uint16_t * create_packet_basic(uint8_t * payload, int size_p)
{
  uint16_t * packet;
  packet = (uint16_t *) malloc((sizeof((uint16_t) size_p)) + (2 * (sizeof(uint16_t))));
  
  int i;
  
  for (i = 0; i < size_p; i++)
  {
    packet[i] = payload[i];
  }

  Serial.println("PRINT I: ");
  Serial.print(i);// 6 - - 1 - 2

  uint8_t checksum_high = 0;
  uint8_t checksum_low = 0;
  uint16_t checksum = 0;

  packet[i] = checksum_high;
  i++;
  packet[i] = checksum_high;
  
  checksum = sum_calc(i - 1, packet);
  
  checksum_high = ((checksum & 0xFF00) >> 8);
  checksum_low = checksum & 0xFF;
  
  packet[i - 1] = checksum_high;
  packet[i] = checksum_low;

  Serial.println("Packet s checksumom: ");
  for (int j = 0; j < (size_p + 2); j++)
  {
    Serial.print(packet[j]);
    Serial.print(", ");
  }
  Serial.println("END");
  return &packet[0];
}


void setup() {
  Serial.begin(9600); // serial start for help print to console
  Serial.println("TEST");
  
  /*uint16_t test_checksum1[18] = {69, 0, 0, 60, 28, 70, 64, 0, 64, 6, 172, 16, 0, 0, 10, 99, 172, 16};
  uint16_t result = 0;
  uint8_t test_checksum2[14] = {28, 70, 64, 0, 64, 6, 172, 16, 0, 0, 10, 99, 172, 16};

  result = sum_calc(18, (uint16_t*) test_checksum1);
  Serial.println("Checksum is: ");
  Serial.print(result);
  Serial.println("");

  uint8_t * packet;
  uint8_t * input;*/
  uint8_t t_s[2] = {0, 4};
  uint8_t seq[2] = {0, 6};
  
  uint16_t * test_ret;
  uint16_t * merged_without_checksum_16;
  uint8_t * merged_without_checksum_8;
  uint8_t * merged_without_checksum_8_correct_size;

  uint16_t chcecksum_result = 0;

  /*test_ret = (uint16_t *) malloc((20 * sizeof(uint16_t)));
  packet = (uint8_t *) malloc((20 * sizeof(uint8_t)));
  input = (uint8_t *) malloc((14 * sizeof(uint8_t)));*/

  
  merged_without_checksum_16 = (uint16_t *) malloc((6 * sizeof(uint16_t)));
  merged_without_checksum_8 = (uint8_t *) malloc((6 * sizeof(uint8_t)));
  merged_without_checksum_16 = merge_packet(t_s, seq, salt, 2);

  merged_without_checksum_8_correct_size = (uint8_t *) malloc((16 * sizeof(uint8_t)));
  merged_without_checksum_8_correct_size_checksum = (uint8_t *) malloc((18 * sizeof(uint8_t)));
  
  Serial.println("Merged packet v maine 16");
  for (int j = 0; j < 6; j++)
  {
    merged_without_checksum_8[j] = (uint8_t) merged_without_checksum_16[j];
    Serial.print(merged_without_checksum_16[j]);
    Serial.print(", ");
  }
  Serial.println("END");
  
  
  //test_ret = create_packet(t_s, seq, test_checksum2, 14);

  /*Serial.println("Packet v maine 16");
  for (int j = 0; j < 20; j++)
  {
    packet[j] = (uint8_t) test_ret[j];
    Serial.print(test_ret[j]);
    Serial.print(", ");
  }
  Serial.println("END");*/

  Serial.println("Packet v maine 8");
  for (int j = 0; j < 6; j++)
  {
    Serial.print(merged_without_checksum_8[j]);
    Serial.print(", ");
    merged_without_checksum_8_correct_size[j] = merged_without_checksum_8[j];
  }
  Serial.println("END");

  for (int j = 6; j < 16; j++)
  {
    merged_without_checksum_8_correct_size[j] = 0;
  }

  /*salted_code[0] = (auth_code_of_arduino[0] ^ salt[0]);
  salted_code[1] = (auth_code_of_arduino[1] ^ salt[1]);
  Serial.print("Xor is: ");
  Serial.print(salted_code[0]);
  Serial.print(", ");
  Serial.print(salted_code[1]);
  Serial.println("");*/
  
  /*BLAKE2s blake;
  
  blake.reset(key, sizeof(key), 32);
  blake.update(salted_code, sizeof(salted_code));
  blake.finalize(hash, 32);*/
  
  /*Serial.println("Key is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(key[i]);
    Serial.print(" ");
  }
  Serial.println("");*/

  /*Serial.println("Salted code is: ");
  for (int i = 0; i < 2; i++)
  {
    Serial.print(salted_code[i]);
    Serial.print(" ");
  }
  Serial.println("");

  Serial.println("Hash is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(hash[i]);
    Serial.print(" ");
  }
  Serial.println("");*/


  
/*
  Serial.println("TEST2");
  
  //blake.reset(key, sizeof(key), 32);
  //blake.update(salted_code, sizeof(salted_code));
  //blake.finalize(hash, 32);
  
  Serial.println("Key is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(key[i]);
    Serial.print(" ");
  }
  Serial.println("");

  Serial.println("Salted code is: ");
  for (int i = 0; i < 2; i++)
  {
    Serial.print(salted_code[i]);
    Serial.print(" ");
  }
  Serial.println("");

  Serial.println("Hash is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(hash[i]);
    Serial.print(" ");
  }
  Serial.println("");*/


  

  Serial.println("Vypocet tajomstva na serverovej strane");
  for (int i = 0; i < 32; i++)
  {
    secret_server[i] = public_key_of_arduino[i];
  }
  
  Curve25519::dh2(secret_server, private_key_of_server);
  Serial.println("Tajomstvo je: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(secret_server[i]);
    Serial.print(", ");
  }
  
  Serial.println("");


  Serial.println("Vypocet tajomstva na arduino strane");
  for (int i = 0; i < 32; i++)
  {
    secret_arduino[i] = public_key_of_server[i];
  }
  
  Curve25519::dh2(secret_arduino, private_key_of_arduino);
  Serial.println("Tajomstvo je: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(secret_arduino[i]);
    Serial.print(", ");
  }
  
  Serial.println("");

  //test test

  
  Serial.println("*****************************TEST CIPHER***********************");
  Serial.println("");


  Serial.print("Original text je: ");
  for (int i = 0; i < /*sizeof(text)*/ 16; i++)
  {
    //Serial.print(merged_without_checksum_8[i]);
    Serial.print(merged_without_checksum_8_correct_size[i]);
    Serial.print(", ");
  }
  Serial.println("");

  speck.setKey(secret_server, 32); //with calculated cipher via DFH

  //cipher_text_correct_size
  //merged_without_checksum_8_correct_size
  speck.encryptBlock(cipher_text_correct_size, merged_without_checksum_8_correct_size);

  //speck.encryptBlock(cipher_text, merged_without_checksum_8);
  /*Serial.print("Zasifrovany text je: ");
  for (int i = 0; i < sizeof(cipher_text); i++)
  {
    Serial.print(cipher_text[i]);
    Serial.print(", ");
  }
  Serial.println("");*/

  Serial.print("Zasifrovany text new je: ");
  for (int i = 0; i < sizeof(cipher_text_correct_size); i++)
  {
    Serial.print(cipher_text_correct_size[i]);
    Serial.print(", ");
  }
  Serial.println("");


  //test_ret = (uint16_t *) malloc((8 * sizeof(uint16_t)));
  //test_ret = create_packet_basic(cipher_text, 6);


  /*Serial.print("Zasifrovany text  + checksum je: ");
  for (int i = 0; i < 8; i++)
  {
    Serial.print(test_ret[i]);
    Serial.print(", ");
  }
  Serial.println("");*/


  //--test na validnost checksumu:

  //--cast to 16

  /*uint16_t calculated_checksum = 0;

  calculated_checksum = sum_calc(6, test_ret);
  Serial.println("Calculated chcecksum is: ");
  Serial.println(calculated_checksum);

  
  Serial.println("");

  Serial.println("Checksum in packet is: ");
  Serial.println(test_ret[6]);
  Serial.println(test_ret[7]);

  uint16_t chceksum_sum = 0;
  chceksum_sum =(((test_ret[6]<<8)&0xFF00) + (test_ret[7]&0xFF));
  Serial.println("Checksum in packet is: ");
  Serial.println(chceksum_sum);*/
  
  speck.decryptBlock(newtext_correct_size, cipher_text_correct_size);
  Serial.print("Desifrovany new text je: ");
  for (int i = 0; i < sizeof(newtext_correct_size); i++)
  {
    Serial.print(newtext_correct_size[i]);
    Serial.print(", ");
  }
  Serial.println("");
  Serial.println("Koniec setup");

  Serial.println("BLA");

  merged_without_checksum_8_correct_size_checksum16 = create_packet_basic(cipher_text_correct_size, 16);

  for (int i = 0; i < 18; i++)
  {
    merged_without_checksum_8_correct_size_checksum[i] = merged_without_checksum_8_correct_size_checksum16[i];
  }
  
  Serial.print("Sifrovany + checksum je: ");
  for (int i = 0; i < 18; i++)
  {
    Serial.print(merged_without_checksum_8_correct_size_checksum[i]);
    Serial.print(", ");
  }

  Serial.print("checksum je: ");
  Serial.print(sum_calc(16, merged_without_checksum_8_correct_size_checksum16));
}

void loop() {
  Serial.println("Som v loope");
  delay(1000);
}
