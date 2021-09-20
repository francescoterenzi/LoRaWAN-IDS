from debug import Debug
from pattern import Pattern
from segment import Segment

class IDS:

    def __init__(self):

        self.d = Debug("ids.txt")

        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}
        self.to_analyze = {}

        self.current_section = 1


    def read_packet(self, p):

        #self.statistics["num_of_packets"] += 1

        if (p.mtype == "Join Request"):
            self.current_section += 1
            #self.statistics["last_section_packets"] = self.statistics["current_section_packets"]
            #self.statistics["current_section_packets"] = 0

        else:
            #self.statistics["current_section_packets"] += 1
            #self.statistics["last_timestamp"] = p.t

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

            self.__clean_undefined(devaddr)

        else:
            if devaddr in self.unconfirmed:
                self.unconfirmed[devaddr].update(p.t)
                
                if devaddr in self.quarantine:

                    elem = self.quarantine[devaddr][0]
                    timestamp = self.quarantine[devaddr][1]
                    pattern = self.confirmed[elem]

                    x = Segment(p.t - timestamp, 0)
                    if x.belongs_to(pattern):
                        self.d.duplicate(devaddr, elem)
                        self.confirmed[devaddr] = self.unconfirmed[devaddr]
                        self.confirmed.pop(elem)
                        self.__clean_undefined(elem)

                    else:
                        new_pattern = self.unconfirmed[devaddr][elem]
                        new_pattern.verified = True
                        self.confirmed[devaddr] = new_pattern
                        self.__check_quar_new_dev(devaddr)

                    self.unconfirmed.pop(devaddr)
                    self.quarantine.pop(devaddr)
                    self.to_analyze.pop(devaddr)

                else:
                    to_analyze = self.to_analyze[devaddr]

                    unconf_pattern = self.unconfirmed[devaddr]

                    for e in to_analyze:
                        conf_pattern = self.confirmed[e]        

                        if conf_pattern.verified:
                            
                            if len(unconf_pattern.segments) == len(conf_pattern.segments):
                                pattern_matching = conf_pattern.equals(unconf_pattern)
                            
                                if pattern_matching:
                                    self.quarantine[devaddr] = (e, p.t)      
                                else:
                                    self.to_analyze[devaddr].remove(e)

                    if len(self.to_analyze[devaddr]) == 0:   
                        self.d.new_dev(devaddr)     
                        self.confirmed[devaddr] = unconf_pattern

                        self.unconfirmed.pop(devaddr)
                        self.to_analyze.pop(devaddr)


            else:
                # it's a new devaddr
                self.unconfirmed[devaddr] = Pattern(p.t)
                self.to_analyze[devaddr] = [elem for elem in self.confirmed]



    def __clean_undefined(self, devaddr):
        to_analyze = self.to_analyze.copy()

        for elem in to_analyze:
            if devaddr in to_analyze[elem]:
                self.to_analyze[elem].remove(devaddr)
            