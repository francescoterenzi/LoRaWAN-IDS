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
        self.num_of_err = 0


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
        print("Num. of devices: " + str(len(self.confirmed)))
        print("Num. of unique devices: " + str(num_of_deveui))
        print("Len. of unconfirmed pattern list: " + str(len(self.unconfirmed)))
        print("Num. of errors: " + str(self.num_of_err))
        print()
        print(30 * "=" + "\n\n")


    def last_section_metrics(self):
        return self.current_section, self.last_section_packets, len(self.confirmed)


    # private methods
    def __elaborate_packet(self, p):

        # device con medie uguali, li togliamo altrimenti si sballa tutto
        if p.dev_eui == "22" or p.dev_eui == "125" or p.dev_eui == "161":
            return

        devaddr = p.dev_addr
        
        if devaddr not in self.confirmed.keys():
            if devaddr in self.unconfirmed.keys():

                # aggiorniamo i dati del device nella lista sospetta
                self.unconfirmed[devaddr].update(p.t)

                current_count = self.unconfirmed[devaddr].n

                # questo device è apparso più di tot. volte -> quality score alto     
                if current_count >= 30:
            
                    duplicate = False
                    m = self.unconfirmed[devaddr].m

                    pattern2 = self.unconfirmed[devaddr]

                    # ricavo una lista inziale di tutti i devaddr da analizzare
                    # cioè tutti i devaddr confermati, tranne quelli della sezione corrente
                    l1 = list(filter(lambda x: x not in self.current_section_devaddr, self.confirmed)) 

                    # ricavo una seconda lista da quella precedente, in cui rimuovo i device
                    # la cui media si discosta notevolmente da quella del devaddr corrente
                    l2 = list(filter(lambda x: abs(self.confirmed[x].m - m) < 10, l1))

                    # ricavo una terza lista da quella precedente, in cui filtro solo gli
                    # elementi che sono duplicati rispetto al devaddr corrente
                    l3 = list(filter(lambda x: self.confirmed[x].equals(pattern2), l2))    

                    if len(l3) >= 1:
                        elem = l3[0]

                        if devaddr.split("_")[0] != elem.split("_")[0]:
                            print("[ERROR] " + devaddr + " and " + elem + " are different!")
                        
                        #if int(devaddr.split("_")[1]) != int(elem.split("_")[1]) + 1:
                        #    print("[MISSING] " + devaddr + " and " + elem)

                        self.confirmed.pop(elem)
                    else:
                        #print("[NEW DEV] " + devaddr + " is a new device!")
                        if int(devaddr.split("_")[1]) > 1:
                            print("[ERROR] " + devaddr + " is not a new device")
                            self.num_of_err += 1

                    self.confirmed[devaddr] = pattern2
                    self.unconfirmed.pop(devaddr)
     
            else:
                # inseriamo il devaddr nella lista sospetta
                pattern = Pattern(devaddr, p.t, self.current_section)
                self.unconfirmed[devaddr] = pattern
        
        else:
            self.confirmed[devaddr].update(p.t)
