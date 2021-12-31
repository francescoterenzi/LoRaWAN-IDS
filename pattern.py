from os import times
from segment import Segment
from time import sleep
import math
import time
import numpy as np
from scipy.stats import ks_2samp

class Pattern:

    def __init__(self, timestamp, e):
        self.timestamp = timestamp
        self.n = 1
        self.e = e
        self.verified = False
        self.segments = []
        #self.alpha = 0.001


    def update(self, timestamp):

        self.n += 1

        old_t = self.timestamp 
        self.timestamp = timestamp

        x = self.timestamp - old_t
        
        found = False
        for s in self.segments:
            if abs(s.mean - x) < self.e:
                found = True
                s.update(x) 
        
        if found:
            self.verified = True

        if not found:
            # new segment
            index = len(self.segments) - 1
            segment = Segment(x, index)
            self.segments.append(segment)
            self.verified = False


    def equals(self, pattern):

        if len(pattern.segments) != len(self.segments):
            return False

        segments = pattern.segments
        for s in segments:
            if not s.belongs_to(self):
                return False
        
        return True


    def contains(self, pattern):
        segments = pattern.segments
        for s in segments:
            if not s.belongs_to(self):
                return False
        return True
                            

    # old equals function, used in mono-segment patterns
    def old_equals(self, pattern2):

        # Kolmogorov–Smirnov test

        x = self.values
        n1 = self.n

        y = pattern2.values
        n2 = pattern2.n

        c_a = math.sqrt( - math.log(self.alpha/2) / 2)
        statistic = ks_2samp(x,y)[0]
        critical_value = c_a * math.sqrt( (n1 + n2) / (n1*n2))

        return statistic <= critical_value