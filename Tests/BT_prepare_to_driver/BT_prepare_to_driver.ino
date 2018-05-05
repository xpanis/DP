String input_msg;
int lenght = 0;
int myTimeout = 250;  // milliseconds for Serial.readString
byte test_msg[18] = {0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 255, 254};
String byte_msg;

void setup()
{
  Serial.begin(9600); // Default communication rate of the Bluetooth module
  Serial.setTimeout(myTimeout);
  for (int i = 0; i < 18; i++)
  {
    byte_msg[i] = test_msg[i];
  }
}


void loop()
{ 
 input_msg = "";
 if(Serial.available() > 0)
 {
    input_msg = Serial.readString(); // Reads the data from the serial port
    lenght = input_msg.length();
    Serial.println("");
    Serial.println("Prislo mi toto START:");
    Serial.println(input_msg);
    Serial.println(input_msg[lenght - 1]);
    Serial.println("Prislo mi toto END:");
    Serial.println("Dlzka je: ");
    Serial.println(lenght);
    Serial.println("");
    Serial.println("TEST2 START");
    //Serial.write(test_msg, 18);
    Serial.println(byte_msg);
    Serial.println("");
    Serial.println("TEST2 END");
    Serial.println("");
    Serial.println("");
 }
}
