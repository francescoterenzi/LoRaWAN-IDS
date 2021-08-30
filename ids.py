# import matplotlib.pyplot as plt
# import numpy as np
# import scipy.stats as stats
# import math
from time import sleep
from pattern import Pattern


class IDS:

    def __init__(self, label):
        self.label = label
        self.current_section = 1
        self.confirmed = {}
        self.unconfirmed = {}
        self.current_section_devaddr = set()
        self.num_of_packets = 0
        self.last_section_packets = 0
        self.current_section_packets = 0
        self.last_timestamp = 0


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

            self.__elaborate_packet(p)
        

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
        print("Num of devices: " + str(len(self.confirmed)))
        print("Num of unique devices: " + str(num_of_deveui))
        print("Len of unconfirmed pattern list: " + str(len(self.unconfirmed)))
        print()
        print(30 * "=" + "\n\n")

        # for elem in self.unconfirmed:
        #    print(elem + " " + str(self.unconfirmed[elem].get_count()))
    

    def last_section_metrics(self):
        return self.current_section, self.last_section_packets, len(self.confirmed)


    # private methods
    def __elaborate_packet(self, p):
        devaddr = p.dev_addr

        if devaddr in self.confirmed.keys():
            self.__update(p)

        else:
            if devaddr in self.unconfirmed.keys():
                # aggiorniamo i dati del device nella lista sospetta
                self.__update(p, False)

                #current_count = self.unconfirmed[devaddr].get_count()
                quality_score = self.unconfirmed[devaddr].quality_score

                # questo device è apparso più di tot. volte -> quality score alto     
                if quality_score >= 0.90:

                    duplicate = False
                    to_analyze = self.__list_to_analyze()

                    for elem in to_analyze:
                   
                        duplicate = self.__verify_duplicate(elem, devaddr)
     
                        # è solo un controllo personale. da rimuovere
                        if devaddr.split("_")[0] != elem.split("_")[0] and duplicate == True:
                            duplicate = False
                            print("[ERROR] " + devaddr + " and " + elem + " are different!")

                        if duplicate:
                            #print("[" + elem + "] and " + "[" + devaddr + "] are duplicate" )
                            #print()
                            self.__merge_devices(elem, devaddr)
                            return

                    self.__set(p)
                    self.unconfirmed.pop(devaddr)

            else:
                # inseriamo il devaddr nella lista sospetta
                self.__set(p, False)


    def __set(self, p, confirmed=True):
        devaddr = p.dev_addr
        if confirmed:
            self.confirmed[devaddr] = self.unconfirmed[devaddr]
        else:
            timestamp = p.t
            pattern = Pattern(devaddr, timestamp)
            self.unconfirmed[devaddr] = pattern


    def __update(self, p, confirmed=True):
        devaddr = p.dev_addr
        if confirmed:
            self.confirmed[devaddr].update(p.t)
        else:
            self.unconfirmed[devaddr].update(p.t)


    def __verify_duplicate(self, devaddr1, devaddr2):
        
        pattern1 = self.confirmed[devaddr1]
        pattern2 = self.unconfirmed[devaddr2]

        return pattern1.equals(pattern2)


    def __merge_devices(self, devaddr1, devaddr2):
        
        pattern2 = self.unconfirmed[devaddr2]
        self.confirmed[devaddr1].merge(pattern2)
        
        self.confirmed[devaddr2] = self.confirmed[devaddr1]
        self.confirmed.pop(devaddr1)


    def __list_to_analyze(self):
        patterns = self.confirmed.copy()
        pattern_keys = set(patterns.keys())
        return pattern_keys - self.current_section_devaddr