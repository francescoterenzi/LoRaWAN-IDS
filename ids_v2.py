from debug import debug_duplicate
from time import sleep
from pattern import Pattern

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
        
        '''
        f = open("result.txt", "a")
        tot_len = len(self.verified) + len(self.not_verified) + len(self.unconfirmed) + len(self.quarantine)
        f.write("len p: " + str(len(self.patterns)) + \
            " len v: " + str(len(self.verified)) + \
                " len n_v: " + str(len(self.not_verified)) + \
                    " len u: " + str(len(self.unconfirmed)) + \
                        " len q: " + str(len(self.quarantine)) +
                        " tot len (v + n_v + u + q) " + str(tot_len) + "\n")
        f.close()
        '''

        devaddr = p.dev_addr

        if devaddr not in self.current:
            self.current.append(devaddr)

        if devaddr in self.verified:
            self.patterns[devaddr].update(p.t)

        elif devaddr in self.not_verified:
            self.patterns[devaddr].update(p.t)
            if self.patterns[devaddr].verified:
                self.verified.append(devaddr)
                self.not_verified.remove(devaddr)

        elif devaddr in self.quarantine:
            self.patterns[devaddr].update(p.t)
            suspect = self.quarantine[devaddr]
            
            pattern1 = self.patterns[devaddr]
            pattern2 = self.patterns[suspect]

            if pattern1.equals(pattern2):
                self.patterns.pop(suspect)
                self.verified.remove(suspect)
                self.removed.append(suspect)      
            
            if self.patterns[devaddr].verified:
                self.verified.append(devaddr)
            else:
                self.not_verified.append(devaddr)
            self.quarantine.pop(devaddr)

        elif devaddr in self.unconfirmed:
            self.patterns[devaddr].update(p.t)
            
            l = list(filter(lambda x: x not in self.removed, self.to_analyze[devaddr]))
            self.to_analyze[devaddr] = l

            to_remove = []
            pattern1 = self.patterns[devaddr]
            for a in self.to_analyze[devaddr]:
                
                pattern2 = self.patterns[a]

                if pattern1.equals(pattern2):
                    self.unconfirmed.remove(devaddr)
                    self.quarantine[devaddr] = a
                    return
                elif pattern2.contains(pattern1):
                    pass
                else:
                    self.to_analyze[devaddr].remove(a)
            
            if len(self.to_analyze[devaddr]) == 0:
                # new conf dev
                self.unconfirmed.remove(devaddr)
                if self.patterns[devaddr].verified:
                    self.verified.append(devaddr)
                else:
                    self.not_verified.append(devaddr)
        
        else:
            # new unconf dev
            self.patterns[devaddr] = Pattern(p.t)
            self.unconfirmed.append(devaddr)

            self.to_analyze[devaddr] = [x for x in self.verified if x not in self.current]
