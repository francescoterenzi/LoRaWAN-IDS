import math
from typing import Pattern

# quality_score(n) = (n / (n + 10))

class IDS:

    # name of the network
    label = "" 
    
    patterns = {}
    unconfirmed = {}

    current_section = 0

    num_of_packets = 0
    last_section_packets = 0
    current_section_packets = 0


    def __init__(self, label):
        self.label = label
        self.current_section += 1


    def read_packet(self, p):
        self.num_of_packets += 1
        
        if (p.mtype == "Join Request"):
            self.current_section += 1
            self.last_section_packets = self.current_section_packets
            self.current_section_packets = 0
            self.current_section_devaddr = []
        else:
            self.current_section_packets += 1
        
        return p.mtype


    def elaborate_pattern(self, p):
        devaddr = p.dev_addr

        if devaddr not in self.patterns:

            if devaddr not in self.unconfirmed:
                self.__init_unconfirmed(p)

            else:
                self.__update_unconfirmed(p)
                    
                if self.unconfirmed[devaddr]["count"] >= 50:
                    unconf_m = self.unconfirmed[devaddr]["interarrival"]
                    unconf_S = self.unconfirmed[devaddr]["variance"]
                    
                    error = 0.2
                    duplicate = False
                    
                    to_analyze = self.patterns.copy()

                    for elem in to_analyze:
                        m = to_analyze[elem]["interarrival"]
                        S = to_analyze[elem]["variance"]
                        
                        if unconf_m >= m - error and unconf_m <= m + error:
                            duplicate = True

                            elem_var = self.patterns[elem]["variance"]
                            devaddr_var = self.unconfirmed[devaddr]["variance"]

                            if devaddr.split("_")[0] != elem.split("_")[0]:
                                print("[ERROR] " + devaddr + " and " + elem + \
                                    " are different! mean1: " + \
                                        str(unconf_m) + " mean2: " + str(m) + \
                                            " var1: " + str(devaddr_var) + " var2: " + str(elem_var))

                            
                            count1 = self.patterns[elem]["count"]
                            mean1 = self.patterns[elem]["interarrival"]
                            M2_1 = self.patterns[elem]["M2"]
                            
                            count2 = self.unconfirmed[devaddr]["count"]
                            mean2 = self.unconfirmed[devaddr]["interarrival"]
                            M2_2 = self.unconfirmed[devaddr]["M2"]

                            delta = mean2 - mean1

                            new_count = count1 + count2
                            delta = mean2 - mean1

                            new_mean = mean1 + delta * (count2/new_count)
                            new_M2 = M2_1 + M2_2 + (delta ** 2) * (count1 * count2/new_count)
                            new_S = new_M2 / (new_count - 1)

                            self.patterns[devaddr] = {
                                "count": new_count,
                                "timestamp" : math.trunc(p.t),
                                "interarrival": new_mean,
                                "M2": new_M2,
                                "variance": new_S
                            }

                            '''
                            print("Change devaddr:")
                            print(elem + " old mean: " + str(self.patterns[elem]["interarrival"]))
                            print(elem + " old M2: " + str(self.patterns[elem]["M2"]))
                            print(elem + " old variance: " + str(self.patterns[elem]["variance"]))
                            print(devaddr + " new mean: " + str(self.unconfirmed[devaddr]["interarrival"]))
                            print(elem + " new M2: " + str(self.unconfirmed[devaddr]["M2"])) 
                            print(devaddr + " new variance: " + str(self.unconfirmed[devaddr]["variance"]))
                            print(devaddr + " comb mean: " + str(self.patterns[devaddr]["interarrival"]))
                            print(devaddr + " comb M2: " + str(self.patterns[devaddr]["M2"]))
                            print(devaddr + " comb variance: " + str(self.patterns[devaddr]["variance"]))
                            print()
                            '''

                            self.patterns.pop(elem)

                    if not duplicate:
                        self.__set_pattern(devaddr, self.unconfirmed[devaddr])
                        #print("New enter:")
                        #print(p.dev_addr + " mean: " + str(self.patterns[p.dev_addr]["interarrival"]))
                        #print(p.dev_addr + " variance: " + str(self.patterns[p.dev_addr]["variance"]))
                        #print()

                    self.unconfirmed.pop(devaddr)

       
        else:
            self.__update_pattern(p)
            #print("Same device:")
            #print(p.dev_addr + " mean: " + str(self.patterns[p.dev_addr]["interarrival"]))
            #print(p.dev_addr + " variance: " + str(self.patterns[p.dev_addr]["variance"]))
            #print()
            #if p.dev_addr == "281_0":
            #    print("[" + p.dev_addr + "]  mean: " + str(self.patterns[p.dev_addr]["interarrival"]))

    def statistics(self):
        # final data
        num_of_joins = self.current_section - 1
        num_of_data = self.num_of_packets - num_of_joins

        # print statistics
        print(30 * "=")
        print()
        print(self.label.upper())

        print()

        print("Num. of overall packets: " + str(self.num_of_packets))
        print("Num. of Data packets: " + str(num_of_data))
        print("Num. of Join Requests: " + str(num_of_joins))
        print("Num. of sections: " + str(self.current_section))
        print()
        print(30 * "=" + "\n\n")

    
    def last_section_statistics(self):
        return self.current_section, self.last_section_packets, len(self.patterns)

       

    def __set_pattern(self, devaddr, dict):
        self.patterns[devaddr] = dict


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
        self.patterns[devaddr]["interarrival"] = m
        self.patterns[devaddr]["M2"] = M2
        self.patterns[devaddr]["variance"] = S


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
        self.unconfirmed[devaddr]["interarrival"] = m
        self.unconfirmed[devaddr]["M2"] = M2
        self.unconfirmed[devaddr]["variance"] = S