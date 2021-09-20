# IDS for LoRaWAN

## Classes:

### IDS
This class represents the core of our programm.
**methods:**
*read_packet(p)*

### Pattern
**methods:**
*update(timestamp)*
*equals(pattern)*
*contains(self, pattern)*

### Segment
**methods:**
*belongs_to(pattern)*
*update(value)*

### Debug
**methods:**
*new_dev(devaddr)*
*duplicate(devaddr1, devaddr2)*