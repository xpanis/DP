#include <Curve25519.h>
#include <BLAKE2s.h>
#include <Crypto.h>
#include <Speck.h>

/*uint8_t wrong_secret[32];

uint8_t public_key_of_server[32] = {174, 243, 69, 129, 50, 14, 32, 63, 61, 38, 104, 233, 157, 59, 18, 146, 231, 38, 134, 104, 218, 18, 237, 151, 178, 213, 104, 139, 155, 21, 222, 119};
uint8_t private_key_of_server[32] = {216, 42, 26, 169, 32, 50, 138, 171, 206, 170, 83, 7, 104, 211, 88, 221, 49, 94, 112, 117, 211, 58, 160, 178, 193, 28, 36, 174, 72, 110, 96, 105};

uint8_t public_key_of_arduino[32] = {183, 213, 11, 131, 18, 199, 146, 88, 127, 147, 102, 167, 60, 161, 231, 11, 241, 151, 138, 19, 234, 41, 102, 5, 114, 12, 135, 164, 112, 135, 31, 65};
uint8_t private_key_of_arduino[32] = {48, 200, 162, 104, 234, 213, 194, 111, 216, 216, 248, 240, 121, 154, 62, 179, 39, 180, 217, 200, 102, 178, 43, 105, 215, 160, 96, 44, 196, 227, 42, 72};*/
uint8_t secret[32] = {16, 29, 211, 181, 107, 23, 26, 25, 8, 122, 106, 92, 17, 35, 223, 136, 149, 91, 46, 98, 186, 41, 148, 25, 139, 129, 156, 99, 37, 103, 49, 49}

uint8_t auth_code[2] = {23,138};
uint8_t salt[2] = {7,32};
uint8_t salted_code[2];
uint8_t hash[32];
uint8_t key[32];

//char text = "Toto je test Text";
char newtext[20];
char cipher[20];

Speck speck;

/*// Generate the secret value "f" and the public value "k".
Curve25519::dh1(k, f);
// Send "k" to the other party.
...
// Read the "k" value that the other party sent to us.
...
// Generate the shared secret in "k" using the previous secret value "f".
if (!Curve25519::dh2(k, f)) {
    // The received "k" value was invalid - abort the session.
    ...
}
// The "k" value can now be used to generate session keys for encryption.
...*/

void setup() {
  Serial.begin(9600); // serial start for help print to console
  Serial.println("TEST");

  /*salted_code[0] = (auth_code[0] ^ salt[0]);
  salted_code[1] = (auth_code[1] ^ salt[1]);
  Serial.print("Xor is: ");
  Serial.print(salted_code[0]);
  Serial.print(", ");
  Serial.print(salted_code[1]);
  
  BLAKE2s blake;
  
  blake.reset(key, sizeof(key), 32);
  blake.update(salted_code, sizeof(salted_code));
  blake.finalize(hash, 32);
  
  Serial.println("Key is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.println(key[i]);
  }
  Serial.println("");

  Serial.println("Salted code is: ");
  for (int i = 0; i < 2; i++)
  {
    Serial.println(salted_code[i]);
  }
  Serial.println("");

  Serial.println("Hash is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.println(hash[i]);
  }
  Serial.println("");

  Serial.println("TEST2");
  
  blake.reset(key, sizeof(key), 32);
  blake.update(salted_code, sizeof(salted_code));
  blake.finalize(hash, 32);
  
  Serial.println("Key is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.println(key[i]);
  }
  Serial.println("");

  Serial.println("Salted code is: ");
  for (int i = 0; i < 2; i++)
  {
    Serial.println(salted_code[i]);
  }
  Serial.println("");

  Serial.println("Hash is: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.println(hash[i]);
  }
  Serial.println("");
*/


  

  /*Serial.println("Vypocet tajomstva");
  for (int i = 0; i < 32; i++)
  {
    secret[i] = public_key_of_arduino[i];
  }
  
  Curve25519::dh2(secret, private_key_of_server);
  Serial.println("Tajomstvo je: ");
  for (int i = 0; i < 32; i++)
  {
    Serial.print(secret[i]);
    Serial.print(", ");
  }*/

  /*Serial.println("*****************************TEST CIPHER***********************");
  speck.setKey(wrong_secret, 32);
  speck.encryptBlock(cipher, text);

  for (int i = 0; i < sizeof(cipher); i++)
  {
    Serial.print(cipher[i]);
    Serial.print(", ");
  }

  Serial.println(" Decryption ... ");

  speck.decryptBlock(newtext, cipher);
  for (int i = 0; i < sizeof(newtext); i++)
  {
    Serial.print(newtext[i]);
    Serial.print(", ");
  }*/
}

void loop() {
  // put your main code here, to run repeatedly:

 

}
