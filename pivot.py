#from debug import Debug
from os import device_encoding
from debug import Debug
from pattern import Pattern
from segment import Segment

class PIVOT:

    def __init__(self, e):

        self.debug = Debug()

        self.e = e

        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}

        self.to_analyze = {}
        self.current_section = 1
        self.detected = 0


    def read_packet(self, p):

        if (p.mtype == "Join Request"):
            self.current_section += 1

        else:
            if self.current_section == 1:
                self.__pre_join(p)
            else:
                self.__main(p)


    def __pre_join(self, p):

        devaddr = p.dev_addr

        if devaddr in self.confirmed:
            self.confirmed[devaddr].update(p.t)
        else:
            self.debug.check_new_device(devaddr)
            self.confirmed[devaddr] = Pattern(p.t, self.e)


    def __main(self, p):

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
                        self.__new_device(devaddr, unconf_pattern)


            else:
                # it's a new devaddr
                self.unconfirmed[devaddr] = Pattern(p.t, self.e)
                self.to_analyze[devaddr] = [elem for elem in self.confirmed]

    def __new_device(self, devaddr, unconf_pattern):
        self.debug.check_new_device(devaddr)    
        self.confirmed[devaddr] = unconf_pattern
        self.unconfirmed.pop(devaddr)
        self.to_analyze.pop(devaddr)

    def __quarantine(self, devaddr, p_timestamp):
        suspect = self.quarantine[devaddr][0]
        timestamp = self.quarantine[devaddr][1]
        pattern = self.confirmed[suspect]

        x = Segment(p_timestamp - timestamp, 0)
        if x.belongs_to(pattern):
            # matching confirmed
            self.detected += 1
            self.confirmed[devaddr] = self.unconfirmed[devaddr]
            self.confirmed.pop(suspect)
            self.__clean(suspect)
            self.debug.check_match(devaddr, suspect)

        else:
            # new device
            self.debug.check_new_device(devaddr) 
            new_pattern = self.unconfirmed[devaddr]
            new_pattern.verified = True
            self.confirmed[devaddr] = new_pattern

        self.unconfirmed.pop(devaddr)
        self.quarantine.pop(devaddr)
        self.to_analyze.pop(devaddr)
        
        # removing the suspect devadrr from the quarantine
        quarantine = self.quarantine.copy()
        for elem in quarantine:
            if quarantine[elem][0] == suspect:
                self.quarantine.pop(elem)

    def __clean(self, devaddr):
        to_analyze = self.to_analyze.copy()

        for elem in to_analyze:
            if devaddr in to_analyze[elem]:
                self.to_analyze[elem].remove(devaddr)

    def get_current_section(self):
        return self.current_section

    def metrics(self):
        number_of_unique_devices = len(self.confirmed)
        number_of_detected_devices = self.detected
        return {
            "NoUD" : len(self.confirmed),
            "NoJ" : self.current_section - 1,
            "NoDD": self.detected,
            "PoDD" : number_of_detected_devices / number_of_unique_devices
        }

    def print_metrics(self):
        number_of_unique_devices = len(self.confirmed)
        number_of_joins = self.current_section - 1
        number_of_detected_devices = self.detected
        percentage_of_detected_devices = number_of_detected_devices / number_of_unique_devices

        print("\n\n======== METRICS FOR THE OPERATOR ========")
        print("Number of Joins (NoJ): ", number_of_joins)
        print("Number of Detected Devices (NoDD): ", number_of_detected_devices)
        print("Number of Unique Devices (NoUD): ", number_of_unique_devices)
        print("Percentage of Detected Devices (PoDD): ", percentage_of_detected_devices)
        print("==========================================\n\n")

    def reset(self):
        self.confirmed = {}
        self.unconfirmed = {}
        self.quarantine = {}

        self.to_analyze = {}
        self.current_section = 1
        self.detected = 0

        self.debug = Debug()


    def get_debug(self):
        self.debug.update_false_negative(self.unconfirmed)
        return self.debug
