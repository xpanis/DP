byte input_msg[102]; input_packet_buffer
byte output_msg[98]; - packet_buffer
int real_length = 0;
bool is_next_zero = false;
int myTimeout = 250;  // milliseconds for Serial.readString

void setup()
{
  Serial.begin(9600); // Default communication rate of the Bluetooth module
  Serial.setTimeout(myTimeout);
  for (int i = 0; i < 102; i++)
  {
    input_msg[i] = 0;
    if (i < 98)
    {
      output_msg[i] = 0;
    }
  }
}


void loop()
{  
  if (Serial.available())
  {
    Serial.readBytes(input_msg, 102);
    Serial.write(input_msg, 102);
    if ((input_msg[0] == 255) && (input_msg[1] == 255))
    {
        for (int i = 0; i < 98; i++)
        {
          is_next_zero = (input_msg[i + 4] == 0)? true : false;
          
          if ((input_msg[i + 2] == 255) && (input_msg[i + 3] == 255) && is_next_zero)
          {
            break;
          }
          else
          {
            output_msg[i] = input_msg[i + 2];
            real_length++;
          }
        }

        Serial.write(output_msg, real_length);

        for (int i = 0; i < 102; i++)
        {
          input_msg[i] = 0;
        }
        real_length = 0;
    }
  }
  delay(5000);
}
