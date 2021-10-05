# IDS for LoRaWAN

## Classes:

### IDS
This class represents the core of our programm. <br/>
Confirmed: all confirmed patterns. There is a one-to-one relationship between a pattern and a Device address.<br/> 
Unconfirmed: all unconfirmed patterns. A unconfirmed pattern could be a new pattern o a duplicate of a confirmed pattern.<br/>
Quarantine: all unconfirmed patterns that have a matching with a confirmed pattern.<br>
<p> [CONFIRMED] U [UNCONFIRMED [QUARANTINE]] </p>
Our goal is to mantain the uncofirmed list as short as po
**methods:** <br/>
*read_packet(p)*

### Pattern
**methods:** <br/>
*update(timestamp)* <br/>
*equals(pattern)* <br/>
*contains(self, pattern)* <br/>

### Segment
**methods:** <br/>
*belongs_to(pattern)* <br/>
*update(value)*

### Debug
**methods:** <br/>
*new_dev(devaddr)* <br/>
*duplicate(devaddr1, devaddr2)*