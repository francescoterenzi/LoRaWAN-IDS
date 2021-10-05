from debug import Debug
from pattern import Pattern
from segment import Segment

class IDS_V2:

    def __init__(self):

        self.debug = Debug("ids_v2.txt")

        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}

        self.to_analyze = {}
        self.current_section = 1


    def read_packet(self, p):

        if (p.mtype == "Join Request"):
            self.current_section += 1

        else:
            if self.current_section == 1:
                self.__pre_join(p)
            else:
                self.__post_join(p)


    def __pre_join(self, p):

        devaddr = p.dev_addr

        if devaddr in self.confirmed:
            self.confirmed[devaddr].update(p.t)
        else:
            self.confirmed[devaddr] = Pattern(p.t)


    def __post_join(self, p):

        devaddr = p.dev_addr  

        if devaddr in self.confirmed:
            self.confirmed[devaddr].update(p.t)
            self.__clean(devaddr)

        else:
            if devaddr in self.unconfirmed:
                self.unconfirmed[devaddr].update(p.t)
                
                if devaddr in self.quarantine:
                    self.__quarantine(devaddr, p.t)

                else:
                    to_analyze = self.to_analyze[devaddr]
                    unconf_pattern = self.unconfirmed[devaddr]


                    verified = list(filter(lambda x: self.confirmed[x].verified, to_analyze))

                    for v in verified:
                        conf_pattern = self.confirmed[v]        
    
                        if len(unconf_pattern.segments) == len(conf_pattern.segments):
                            pattern_matching = conf_pattern.contains(unconf_pattern)
                        
                            if pattern_matching:
                                self.quarantine[devaddr] = (v, p.t)      
                            else:
                                self.to_analyze[devaddr].remove(v)

                    if len(self.to_analyze[devaddr]) == 0:
                        self.__new_device(devaddr, unconf_pattern)   

            else:
                self.unconfirmed[devaddr] = Pattern(p.t)
                self.to_analyze[devaddr] = list(self.confirmed.keys())


    def __quarantine(self, devaddr, p_timestamp):
        suspect = self.quarantine[devaddr][0]
        timestamp = self.quarantine[devaddr][1]
        pattern = self.confirmed[suspect]

        x = Segment(p_timestamp - timestamp, 0)
        if x.belongs_to(pattern):
            self.debug.duplicate(devaddr, suspect)
            self.confirmed[devaddr] = self.unconfirmed[devaddr]
            self.confirmed.pop(suspect)
            self.__clean(suspect)

        else:
            new_pattern = self.unconfirmed[devaddr][suspect]
            self.confirmed[devaddr] = new_pattern

        self.unconfirmed.pop(devaddr)
        self.quarantine.pop(devaddr)
        self.to_analyze.pop(devaddr)


    def __new_device(self, devaddr, unconf_pattern):
        self.debug.new_dev(devaddr)     
        self.confirmed[devaddr] = unconf_pattern
        self.unconfirmed.pop(devaddr)
        self.to_analyze.pop(devaddr)



    def __clean(self, devaddr):
        to_analyze = self.to_analyze.copy()

        for elem in to_analyze:
            if devaddr in to_analyze[elem]:
                self.to_analyze[elem].remove(devaddr)

# n devices
# n of join request
# n of packets
