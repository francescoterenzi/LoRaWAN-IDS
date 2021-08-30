import math
from pattern import Pattern

# quality_score(n) = (n / (n + 10))

class IDS:

    # name of the network
    label = "" 
    
    patterns = {}
    unconfirmed = {}

    current_section = 0
    current_section_devaddr = set()

    num_of_packets = 0
    last_section_packets = 0
    current_section_packets = 0
    last_timestamp = 0


    def __init__(self, label):
        self.label = label
        self.current_section += 1


    def read_packet(self, p):
        self.num_of_packets += 1
        
        if (p.mtype == "Join Request"):
            self.current_section += 1
            self.last_section_packets = self.current_section_packets
            self.current_section_packets = 0
            self.current_section_devaddr = set()

        else:
            self.current_section_packets += 1
            self.current_section_devaddr.add(p.dev_addr)
            self.last_timestamp = p.t
        
        return p.mtype


    def elaborate_pattern(self, p):
        devaddr = p.dev_addr

        if devaddr not in self.patterns:

            if devaddr not in self.unconfirmed:
                # inseriamo il devaddr nella lista sospetta
                self.__init_unconfirmed(p)

            else:
                # aggiorniamo i dati del device nella lista sospetta
                self.__update_unconfirmed(p)

                current_count = self.unconfirmed[devaddr].get_count()

                # se questo device è apparso più di tot. volte allora lo possiamo analizzare     
                if current_count >= 65:
                    
                    duplicate = False
                    to_analyze = self.__list_to_analyze()

                    for elem in to_analyze:
                   
                        duplicate = self.__verify_duplicate(elem, devaddr)
     
                        # è solo un controllo personale. da rimuovere
                        if devaddr.split("_")[0] != elem.split("_")[0] and duplicate == True:
                            #duplicate = False
                            print("[ERROR] " + devaddr + " and " + elem + " are different!")

                        if duplicate:
                            #print("[" + elem + "] and " + "[" + devaddr + "] are duplicate" )
                            #print()
                            self.__merge_devices(elem, devaddr)
                            #self.unconfirmed.pop(devaddr)
                            return

                    self.__set_pattern(devaddr)
                    self.unconfirmed.pop(devaddr)

        else:
            self.__update_pattern(p)


    def statistics(self):
        # final data
        num_of_joins = self.current_section - 1
        num_of_data = self.num_of_packets - num_of_joins
        num_of_deveui = len(set( [elem.split("_")[0] for elem in self.patterns] ))

        # print statistics
        print(30 * "=")
        print()
        print(self.label.upper())

        print()

        print("Num. of overall packets: " + str(self.num_of_packets))
        print("Num. of Data packets: " + str(num_of_data))
        print("Num. of Join Requests: " + str(num_of_joins))
        print("Num. of sections: " + str(self.current_section))
        print("Num of devices: " + str(len(self.patterns)))
        print("Num of unique devices: " + str(num_of_deveui))
        print("Len of unconfirmed pattern list: " + str(len(self.unconfirmed)))
        print()
        print(30 * "=" + "\n\n")

    
    def last_section_statistics(self):
        return self.current_section, self.last_section_packets, len(self.patterns)


    # private methods
    def __set_pattern(self, devaddr):
        self.patterns[devaddr] = self.unconfirmed[devaddr]


    def __init_unconfirmed(self, packet):
        devaddr = packet.dev_addr
        timestamp = packet.t
        pattern = Pattern(devaddr, timestamp)
        self.unconfirmed[devaddr] = pattern


    def __update_pattern(self, p):
        devaddr = p.dev_addr
        self.patterns[devaddr].update(p.t)


    def __update_unconfirmed(self, p):
        devaddr = p.dev_addr
        self.unconfirmed[devaddr].update(p.t)


    def __verify_duplicate(self, devaddr1, devaddr2):
        
        pattern1 = self.patterns[devaddr1]
        pattern2 = self.unconfirmed[devaddr2]

        return pattern1.equals(pattern2)


    def __merge_devices(self, devaddr1, devaddr2):
        
        pattern2 = self.unconfirmed[devaddr2]
        self.patterns[devaddr1].merge(pattern2)
        
        self.patterns[devaddr2] = self.patterns[devaddr1]
        self.patterns.pop(devaddr1)

    def __list_to_analyze(self):
        patterns = self.patterns.copy()
        pattern_keys = set(patterns.keys())
        return pattern_keys - self.current_section_devaddr