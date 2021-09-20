from debug import Debug
from time import sleep
from pattern import Pattern
from segment import Segment

class IDS_V2:

    def __init__(self):
        
        self.section = 1
        
        self.patterns = {}

        self.verified = []
        self.not_verified = []
        self.unconfirmed = []
        self.quarantine = {}

        self.to_analyze = {}
        self.removed = []
        self.current = []

        self.d = Debug("ids_v2.txt")


    def read_packet(self, p):

        if (p.mtype == "Join Request"):
            self.section += 1
            self.current.clear()

        else:
            if self.section == 1:
                self.__pre_join(p)
            else:
                self.__post_join(p)


    def __pre_join(self, p):

        devaddr = p.dev_addr

        if devaddr in self.patterns:
            # already seen
            self.patterns[devaddr].update(p.t)
            if devaddr in self.not_verified and self.patterns[devaddr].verified:
                self.verified.append(devaddr)
                self.not_verified.remove(devaddr)
         
        else:
            # new dev
            self.patterns[devaddr] = Pattern(p.t)
            self.not_verified.append(devaddr)


    def __post_join(self, p):

        devaddr = p.dev_addr

        if devaddr not in self.current:
            self.current.append(devaddr)

        if devaddr in self.unconfirmed:
            self.patterns[devaddr].update(p.t)
            pattern1 = self.patterns[devaddr]

            for a in self.to_analyze[devaddr]:

                if a in self.removed and a not in self.current:
                    self.to_analyze[devaddr].remove(a)
                
                else:
                    pattern2 = self.patterns[a]

                    if pattern2.contains(pattern1):
                        if len(pattern1.segments) == len(pattern2.segments):
                            self.unconfirmed.remove(devaddr)
                            self.quarantine[devaddr] = a
                            return
                    else:
                        self.to_analyze[devaddr].remove(a)
                
            if len(self.to_analyze[devaddr]) == 0:
                # new conf dev
                self.d.new_dev(devaddr)

                self.unconfirmed.remove(devaddr)
                if self.patterns[devaddr].verified:
                    self.verified.append(devaddr)
                else:
                    self.not_verified.append(devaddr)


        elif devaddr in self.quarantine:
            #self.patterns[devaddr].update(p.t)
            
            x = p.t - self.patterns[devaddr].timestamp

            self.patterns[devaddr].update(p.t)
            segment = Segment(x, 0)

            suspect = self.quarantine[devaddr]
            pattern = self.patterns[suspect]

            if segment.belongs_to(pattern):
                self.d.duplicate(devaddr, suspect)

                self.patterns.pop(suspect)
                self.verified.remove(suspect)
                self.removed.append(suspect)      
            
            if self.patterns[devaddr].verified:
                self.verified.append(devaddr)
            else:
                self.not_verified.append(devaddr)
            
            self.quarantine.pop(devaddr)

        elif devaddr in self.not_verified:
            self.patterns[devaddr].update(p.t)
            if self.patterns[devaddr].verified:
                self.verified.append(devaddr)
                self.not_verified.remove(devaddr)
        
        elif devaddr in self.verified:
            self.patterns[devaddr].update(p.t)

        
        else:
            # new unconf dev
            self.patterns[devaddr] = Pattern(p.t)
            self.unconfirmed.append(devaddr)

            self.to_analyze[devaddr] = self.verified
