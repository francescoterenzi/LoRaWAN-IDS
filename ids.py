import math
import time

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

                # se questo device è apparso più di tot. volte allora lo possiamo analizzare     
                if self.unconfirmed[devaddr]["count"] >= 65:
                    
                    duplicate = False
                    
                    unconf_m = self.unconfirmed[devaddr]["interarrival"]
                    unconf_S = math.sqrt(self.unconfirmed[devaddr]["variance"])
                    unconf_c = self.unconfirmed[devaddr]["count"]

                    to_analyze = self.patterns.copy()
                    l = set(to_analyze.keys())
                    final_list = l - self.current_section_devaddr
                                       
                    for elem in final_list:
                        
                        m = to_analyze[elem]["interarrival"]
                        S = to_analyze[elem]["variance"]
                        count = to_analyze[elem]["count"]

                        #if elem == "166_6" and devaddr == "166_7":
                        #    print(self.__verify_duplicate(m, unconf_m, S, unconf_S, count))
                        #    exit()
                        
                        duplicate = self.__verify_duplicate(m, unconf_m, S, unconf_S, count, unconf_c)

                        '''
                        if duplicate == True:
                            print("are " + elem + " and " + devaddr + " the same?")
                            print("m1: " + str(m) + " m2: " + str(unconf_m))
                            print()
                            time.sleep(1)
                        '''

                        # è solo un controllo personale. da rimuovere
                        if devaddr.split("_")[0] != elem.split("_")[0] and duplicate == True:
                            #duplicate = False
                            
                            print("[ERROR] " + devaddr + " and " + elem + \
                                " are different! mean1: " + \
                                    str(unconf_m) + " mean2: " + str(m))

                        if duplicate:
                            #print("[" + elem + "] and " + "[" + devaddr + "] are duplicate" )
                            #print()
                            self.__merge_devices(elem, p)
                            self.unconfirmed.pop(devaddr)
                            return

                    self.__set_pattern(devaddr)
                    self.unconfirmed.pop(devaddr)
                
                else:
                    to_analyze = self.unconfirmed.copy()
                    for elem in to_analyze:
                        if to_analyze[elem]["timestamp"] <= self.last_timestamp - 100000:
                            self.unconfirmed.pop(elem)
        else:
            self.__update_pattern(p)
            '''
            print("Same device:")
            print(p.dev_addr + " mean: " + str(self.patterns[p.dev_addr]["interarrival"]))
            print(p.dev_addr + " variance: " + str(self.patterns[p.dev_addr]["variance"]))
            '''


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
        
        '''
        to_analyze = self.unconfirmed.copy()

        for elem in to_analyze:
            if (elem.split("_")[1] == "0"):
                print(elem + " " + str(self.unconfirmed[elem]["timestamp"]) + " " + str(self.unconfirmed[elem]["count"] + 1))
        
        print()
        print(self.last_timestamp)
        #time.sleep(1)
        '''


    
    def last_section_statistics(self):
        return self.current_section, self.last_section_packets, len(self.patterns)


    def get_deveui(self):
        return [ elem.split("_")[0] for elem in self.patterns ]


    # private methods
    def __set_pattern(self, devaddr):
        self.patterns[devaddr] = self.unconfirmed[devaddr]


    def __init_unconfirmed(self, elem):

        self.unconfirmed[elem.dev_addr] = {
            "count": 0,
            "timestamp" : math.trunc(elem.t),
            "interarrival": 0,
            "M2": 0,
            "variance": 0
        }


    def __update_pattern(self, p):
        devaddr = p.dev_addr

        t = self.patterns[devaddr]["timestamp"]
        m = self.patterns[devaddr]["interarrival"]
        n = self.patterns[devaddr]["count"] + 1
        M2 = self.patterns[devaddr]["M2"]
      
        new_t = math.trunc(p.t)
        x = new_t - t

        delta = x - m
        m += delta / (n -1)
        M2 += delta * (x - m)

        S = M2 / (n -1)

        self.patterns[devaddr]["count"] = n
        self.patterns[devaddr]["timestamp"] = new_t
        self.patterns[devaddr]["interarrival"] = round(m, 4)
        self.patterns[devaddr]["M2"] = M2
        self.patterns[devaddr]["variance"] = round(S, 4)


    def __update_unconfirmed(self, p):
        devaddr = p.dev_addr

        t = self.unconfirmed[devaddr]["timestamp"]
        m = self.unconfirmed[devaddr]["interarrival"]
        n = self.unconfirmed[devaddr]["count"] + 1
        M2 = self.unconfirmed[devaddr]["M2"]
    
        new_t = math.trunc(p.t)
        x = new_t - t

        delta = x - m
        m += delta / n
        M2 += delta * (x - m)

        S = 0
        if n > 1:
            S = M2 / (n - 1)

        self.unconfirmed[devaddr]["count"] = n
        self.unconfirmed[devaddr]["timestamp"] = new_t
        self.unconfirmed[devaddr]["interarrival"] = round(m, 4)
        self.unconfirmed[devaddr]["M2"] = M2
        self.unconfirmed[devaddr]["variance"] = round(S, 4)


    def __verify_duplicate(self, m1, m2, S_1, S_2, count1, count2):
        
        dev_1 = (math.sqrt(S_1) / math.sqrt(count1)) ** 2
        dev_2 = (math.sqrt(S_2) / math.sqrt(count2)) ** 2

        z_test = abs(m2 - m1) / math.sqrt(dev_1 + dev_2)
        #print(z_test)
        return z_test <= 4

        #error = 0.7
        #margin = 3.5

        #return abs(m2 - m1) <= error and abs(std_S_2 - std_S_1) <= margin


    def __merge_devices(self, devaddr1, p):

        devaddr2 = p.dev_addr

        count1 = self.patterns[devaddr1]["count"]
        mean1 = self.patterns[devaddr1]["interarrival"]
        M2_1 = self.patterns[devaddr1]["M2"]
        
        count2 = self.unconfirmed[devaddr2]["count"]
        mean2 = self.unconfirmed[devaddr2]["interarrival"]
        M2_2 = self.unconfirmed[devaddr2]["M2"]

        delta = mean2 - mean1
        new_count = count1 + count2
        delta = mean2 - mean1

        new_mean = mean1 + delta * (count2/new_count)
        new_M2 = M2_1 + M2_2 + (delta ** 2) * (count1 * count2/new_count)
        new_S = new_M2 / (new_count - 1)

        self.patterns[devaddr2] = {
            "count": new_count,
            "timestamp" : math.trunc(p.t),
            "interarrival": round(new_mean, 4),
            "M2": new_M2,
            "variance": round(new_S, 4)
        }

        self.patterns.pop(devaddr1)