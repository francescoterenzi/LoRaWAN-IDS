from time import sleep
from pattern import Pattern
import numpy as np

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
        self.num_of_err = 0


    def read_packet(self, p):
        self.num_of_packets += 1

        #if self.num_of_packets % 1000 == 0:
        #    print(self.num_of_packets)

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
        print("Num. of devices: " + str(len(self.confirmed)))
        print("Num. of unique devices: " + str(num_of_deveui))
        print("Len. of unconfirmed pattern list: " + str(len(self.unconfirmed)))
        print("Num. of errors: " + str(self.num_of_err))
        print()
        print(30 * "=" + "\n\n")

        '''
        f = open("test.txt", "w")
        for elem in sorted(self.confirmed):
            m = self.confirmed[elem].distribution.m
            l = self.confirmed[elem].distribution.lowest
            h = self.confirmed[elem].distribution.highest
            r = self.confirmed[elem].distribution.range
            n = self.confirmed[elem].distribution.n + 1
            f.write(elem + "\t" + str(m) + "\t" + str(l) + "\t" + str(h) + "\t" + str(r) + "\t" + str(n)+ "\n")
        f.close()
        '''


    def last_section_metrics(self):
        return self.current_section, self.last_section_packets, len(self.confirmed)


    # private methods
    def __elaborate_packet(self, p):

        if p.dev_eui == "22" or p.dev_eui == "125" or p.dev_eui == "161":
            return

        devaddr = p.dev_addr

        #if devaddr in self.confirmed.keys():
        #    self.confirmed[devaddr].update(p.t)

        
        if devaddr not in self.confirmed.keys():
            if devaddr in self.unconfirmed.keys():

                # aggiorniamo i dati del device nella lista sospetta
                self.unconfirmed[devaddr].update(p.t)

                current_count = self.unconfirmed[devaddr].n
                #quality_score = self.unconfirmed[devaddr].quality_score

                # questo device è apparso più di tot. volte -> quality score alto     
                if current_count >= 30:

                    duplicate = False
                    #to_analyze = self.__list_to_analyze()

                    #print(len(to_analyze))
                    
                    pattern2 = self.unconfirmed[devaddr]

                    to_analyze = self.confirmed.keys() - list(self.current_section_devaddr)

                    for elem in to_analyze:
                        
                        if abs(self.unconfirmed[devaddr].m - self.confirmed[elem].m) < 10:
                            pattern1 = self.confirmed[elem]
                            
                            duplicate = pattern1.equals(pattern2)

                            #print(duplicate)

                            # è solo un controllo personale. da rimuovere
                            if devaddr.split("_")[0] != elem.split("_")[0] and duplicate == True:
                                #duplicate = False
                                print("[ERROR] " + devaddr + " and " + elem + " are different!")

                            #if int(devaddr.split("_")[1]) != int(elem.split("_")[1]) + 1 and duplicate == True:
                            #    print("[MISSING] " + devaddr + " and " + elem)

                            if duplicate:
                                # appaertengono allo stesso device -> merge!
                                #print("[DUPLICATE] " + devaddr + " and " + elem + " are the same device!")
                                #self.confirmed[elem].merge(pattern2)
                                #self.confirmed[devaddr] = self.confirmed[elem]
                                
                                self.confirmed[devaddr] = pattern2

                                self.confirmed.pop(elem)
                                self.unconfirmed.pop(devaddr)
                                return
                        
                    if not duplicate:
                        #print("[NEW DEV] " + devaddr + " is a new device!")
                        if int(devaddr.split("_")[1]) > 1:
                            print("[ERROR] " + devaddr + " is not a new device")
                            
                            for elem in self.confirmed:
                                if elem.split("_")[0] == devaddr.split("_")[0]:
                                    m1 = self.confirmed[elem].m
                                    n1 = self.confirmed[elem].n
                                    m2 = self.unconfirmed[devaddr].m
                                    n2 = self.unconfirmed[devaddr].n
                                    print(elem + " m1: " + str(m1) + " n1: " + str(n1))
                                    print(devaddr + " m2: " + str(m2) + " n2: " + str(n2))

                            print()
                            self.num_of_err += 1 
                        
                        self.confirmed[devaddr] = pattern2
                    
                    self.unconfirmed.pop(devaddr)

            else:
                # inseriamo il devaddr nella lista sospetta
                pattern = Pattern(devaddr, p.t, self.current_section)
                self.unconfirmed[devaddr] = pattern
        
        else:
            self.confirmed[devaddr].update(p.t)