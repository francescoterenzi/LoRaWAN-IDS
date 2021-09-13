from pattern import Pattern
from segment import Segment

class IDS:

    def __init__(self):

        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}

        self.to_analyze = {}

        self.statistics = {
            "current_section" : 1,
            "num_of_packets" : 0,
            "last_section_packets" : 0,
            "current_section_packets" : 0,
            "last_timestamp" : 0,
            "num_of_err" : 0
        }

        # log file
        self.f = open("result.txt", "w")
        #self.f.write(label.upper() + "\n\n")
        self.f.close()


    def read_packet(self, p):

        self.statistics["num_of_packets"] += 1

        if (p.mtype == "Join Request"):
            self.statistics["current_section"] += 1
            self.statistics["last_section_packets"] = self.statistics["current_section_packets"]
            self.statistics["current_section_packets"] = 0
           
            # log file
            self.f = open("result.txt", "a")
            self.f.write("\n\nSECTION n." + str(self.statistics["current_section"]) + "\n")
            self.f.close()

        else:
            self.statistics["current_section_packets"] += 1
            self.statistics["last_timestamp"] = p.t

            if self.statistics["current_section"] == 1:
                self.__pre_join(p)
            else:
                self.__post_join(p)


    def get_statistics(self):
        num_of_deveui = len(set( [elem.split("_")[0] for elem in self.confirmed] ))
        return self.statistics, len(self.confirmed), len(self.unconfirmed), num_of_deveui


    def __pre_join(self, p):

        devaddr = p.dev_addr

        if devaddr in self.confirmed:
            self.confirmed[devaddr].update(p.t)
         
        else:
            self.confirmed[devaddr] = Pattern(p.t)

            # log file
            self.f = open("result.txt", "a")
            self.f.write("[1st DEV] " + devaddr +"\n")
            self.f.close()


    def __post_join(self, p):

        devaddr = p.dev_addr  

        if devaddr in self.confirmed:

            #prev = self.confirmed[devaddr].verified
            self.confirmed[devaddr].update(p.t)
            #post = self.confirmed[devaddr].verified

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
                        self.confirmed[devaddr] = self.unconfirmed[devaddr]
                        self.confirmed.pop(elem)
                        self.__clean_undefined(elem)
                        self.__check_duplicate(devaddr, elem)

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
                        self.confirmed[devaddr] = unconf_pattern

                        self.unconfirmed.pop(devaddr)
                        self.to_analyze.pop(devaddr)

                        self.__check_new_dev(devaddr)

            else:
                # it's a new devaddr
                self.unconfirmed[devaddr] = Pattern(p.t)
                self.to_analyze[devaddr] = [elem for elem in self.confirmed]
                
                # log file
                self.f = open("result.txt", "a")
                self.f.write("[UNCONF DEV] " + devaddr + "\n")
                self.f.close()


    def __check_duplicate(self, devaddr1, devaddr2):
        self.f = open("result.txt", "a")
        deveui1 = devaddr1.split("_")[0]
        deveui2 = devaddr2.split("_")[0]
        
        seq1 = int(devaddr1.split("_")[1])
        seq2 = int(devaddr2.split("_")[1])

        if deveui1 != deveui2:
            self.f.write("[DUPLICATE ERROR] " + devaddr1 + " and" + devaddr2 + " don't belong to the same dev\n")
            self.num_of_err += 1
        elif abs(seq1 - seq2) > 1:
            curr_len = len(self.confirmed[devaddr1].segments)
            miss_len_str = ""

            for elem in self.unconfirmed.keys():
                if elem.split("_")[0] == deveui1:
                    miss_len_str += str(len(self.unconfirmed[elem].segments)) + " " + elem + " " 

            self.f.write("[DUPLICATE MISSING] " + devaddr1 + " and " + devaddr2 + " are not consecutive." \
            " (curr_len: " + str(curr_len) + ", miss_len: " + miss_len_str + ")\n")

            self.statistics["num_of_err"] += 1
        else:
            self.f.write("[DUPLICATE] " + devaddr2 + " and " + devaddr1 + " belong to the same dev\n")
        self.f.close()
    

    def __check_new_dev(self, devaddr):
        self.f = open("result.txt", "a")
        count = devaddr.split("_")[1]
        if int(count) >= 1:
            self.f.write("[NEW DEV ERROR] " + devaddr + " is not a new dev\n")
        else:
            self.f.write("[NEW DEV] " + devaddr + " is a new device\n")
        self.f.close()


    def __check_quar_new_dev(self, devaddr):
        self.f = open("result.txt", "a")
        count = devaddr.split("_")[1]
        if int(count) >= 1:
            self.f.write("[QUAR - >NEW DEV ERROR] " + devaddr + " is not a new dev\n")
        else:
            self.f.write("[QUAR -> NEW DEV] " + devaddr + " is a new device\n")
        self.f.close()


    def __clean_undefined(self, devaddr):
        to_analyze = self.to_analyze.copy()

        #self.to_analyze = filter(lambda x: (x%2 == 0), numbers)

        for elem in to_analyze:
            if devaddr in to_analyze[elem]:
                self.to_analyze[elem].remove(devaddr)
            