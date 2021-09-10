from hashlib import new
from random import triangular
from time import sleep
from typing import ContextManager
from pattern import Pattern
from segment import Segment

class IDS:

    def __init__(self, label):
        
        self.label = label
        self.current_section = 1

        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}

        self.to_analyze = {}

        self.num_of_packets = 0
        self.last_section_packets = 0
        self.current_section_packets = 0
        self.last_timestamp = 0
        self.num_of_err = 0

        self.f = open("result.txt", "w")
        self.f.close()


    def read_packet(self, p):
        self.num_of_packets += 1

        if (p.mtype == "Join Request"):
            self.current_section += 1
            self.last_section_packets = self.current_section_packets
            self.current_section_packets = 0
            self.f = open("result.txt", "a")
            self.f.write("\n\nSECTION n." + str(self.current_section) + "\n")
            self.f.close()

        else:
            self.current_section_packets += 1
            self.last_timestamp = p.t

            if self.current_section == 1:
                self.__first_section(p)
            else:
                self.__following_sections(p)
        

    def statistics(self):
        # final data
        num_of_joins = self.current_section - 1
        num_of_data = self.num_of_packets - num_of_joins
        num_of_deveui = len(set( [elem.split("_")[0] for elem in self.confirmed] ))

        # print statistics
        print(30 * "=")
        print()
        print(self.label.upper())

        print()

        print("Num. of overall packets: " + str(self.num_of_packets))
        print("Num. of Data packets: " + str(num_of_data))
        print("Num. of Join Requests: " + str(num_of_joins))
        print("Num. of sections: " + str(self.current_section))
        print("Num. of devices: " + str(len(self.confirmed)))
        print("Num. of unique devices: " + str(num_of_deveui))
        print("Len. of unconfirmed pattern list: " + str(len(self.unconfirmed)))
        print("Num. of errors: " + str(self.num_of_err))
        print()
        print(30 * "=" + "\n\n")


    def last_section_metrics(self):
        return self.current_section, self.last_section_packets, len(self.confirmed)


    # private methods
    def __first_section(self, p):

        devaddr = p.dev_addr

        if devaddr in self.confirmed.keys():
            self.confirmed[devaddr].update(p.t)
         
        else:
            self.confirmed[devaddr] = Pattern(p.t)
            self.f = open("result.txt", "a")
            self.f.write("[1st DEV] " + devaddr +"\n")
            self.f.close()


    def __following_sections(self, p):

        devaddr = p.dev_addr
        
        #print()
        #print(devaddr)     

        if devaddr in self.confirmed.keys():
            self.confirmed[devaddr].update(p.t)
            #print("[UPDATE] " + devaddr)
            self.__clean_undefined(devaddr)

        else:
            if devaddr in self.unconfirmed:
                self.unconfirmed[devaddr].update(p.t)
                
                if devaddr in self.quarantine:

                    elem = self.quarantine[devaddr][0]
                    timestamp = self.quarantine[devaddr][1]
                    pattern = self.confirmed[elem]

                    x = Segment(p.t - timestamp)
                    if x.belongs_to(pattern):
                        #print("[DUPLICATE] " + devaddr + " " + elem)

                        self.confirmed[devaddr] = self.unconfirmed[devaddr]

                        self.__clean_undefined(elem)
                        self.confirmed.pop(elem)

                        self.__check_duplicate(devaddr, elem)

                    else:
                        print("[QUAR -> NEW DEV] " + devaddr)
                        #self.__check_new_dev(devaddr)
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
                    segments = unconf_pattern.segments

                    for e in to_analyze:

                        conf_pattern = self.confirmed[e]        

                        if conf_pattern.verified:

                            pattern_matching = True
                            for s in segments:
                                if not s.belongs_to(conf_pattern):
                                    pattern_matching = False
                                    break
                            
                            if pattern_matching:
                                if len(unconf_pattern.segments) == len(conf_pattern.segments):
                                    # hanno lo stesso pattern, devo aspettare il prossimo pacchetto
                                    #print("[QUARANTINE] " + devaddr + " " + e)
                                    self.quarantine[devaddr] = (e, p.t)
                            
                            else:
                                self.to_analyze[devaddr].remove(e)

                    if len(self.to_analyze[devaddr]) == 0:        
                        #print("[NEW DEV] " + devaddr)
                        self.confirmed[devaddr] = unconf_pattern

                        self.unconfirmed.pop(devaddr)
                        self.to_analyze.pop(devaddr)

                        self.__check_new_dev(devaddr)

            else:
                # it's a new devaddr
                self.unconfirmed[devaddr] = Pattern(p.t)
                self.to_analyze[devaddr] = [elem for elem in self.confirmed]

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
            self.f.write("[DUPLICATE MISSING] " + devaddr1 + " and " + devaddr2 + " are not consecutive\n")
            self.num_of_err += 1
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
        for elem in to_analyze:
            if devaddr in to_analyze[elem]:
                self.to_analyze[elem].remove(devaddr)
            