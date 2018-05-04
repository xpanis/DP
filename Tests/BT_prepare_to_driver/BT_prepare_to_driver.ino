String input_msg;
int lenght = 0;
int myTimeout = 250;  // milliseconds for Serial.readString

void setup()
{
  Serial.begin(9600); // Default communication rate of the Bluetooth module
  Serial.setTimeout(myTimeout);
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
    Serial.println("");
 }
}
