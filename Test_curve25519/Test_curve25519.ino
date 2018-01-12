#include <Curve25519.h>


uint8_t f1[32];
uint8_t k1[32];

uint8_t f2[32];
uint8_t k2[32];

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
  // put your setup code here, to run once:
  Serial.begin(9600); // serial start for help print to console
  
  Curve25519::dh1(k1, f1);
  Curve25519::dh1(k2, f2);

  
  Serial.println("Verejny kluc K1");
  for (int i = 0; i<32; i++)
  {
    Serial.print(k1[i]);
  }
  Serial.println("");

  Serial.println("Sukromny kluc F1");
  for (int i = 0; i<32; i++)
  {
    Serial.print(f1[i]);
  }
  Serial.println("");

  
  Serial.println("Verejny kluc 21");
  for (int i = 0; i<32; i++)
  {
    Serial.print(k2[i]);
  }
  Serial.println("");

  Serial.println("Sukromny kluc F2");
  for (int i = 0; i<32; i++)
  {
    Serial.print(f2[i]);
  }
  Serial.println("");
  

  Curve25519::dh2(k2, f1);
  Curve25519::dh2(k1, f2);

  Serial.println("Tajomstvo 1");
  for (int i = 0; i<32; i++)
  {
    Serial.print(k2[i]);
  }
  Serial.println("");

  Serial.println("Tajomstvo 2");
  for (int i = 0; i<32; i++)
  {
    Serial.print(k1[i]);
  }
  Serial.println("");

  int i = 0;
  bool flag = true;

  while (i < 32)
  {
    if (k1[i] != k2[i])
      flag = false;
    if (!flag)
      break;
    i++;
  }

  Serial.println(i);

  if (i == 32)
    Serial.println("Zdielane tajomstva sa Zhoduju!");
  else
    Serial.println("Zdielane tajomstva sa NEzhoduju!");
}

void loop() {
  // put your main code here, to run repeatedly:

 

}
