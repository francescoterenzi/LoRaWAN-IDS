from os import times
from segment import Segment
from time import sleep
import math
import time
import numpy as np
from scipy.stats import ks_2samp

class Pattern:

    def __init__(self, timestamp):
        self.timestamp = timestamp
        self.n = 1
        self.verified = False
        self.segments = []
        self.alpha = 0.001


    def update(self, timestamp):

        len_before = len(self.segments)

        self.n += 1

        old_t = self.timestamp 
        self.timestamp = timestamp

        x = self.timestamp - old_t
        
        found = False
        for s in self.segments:
            if abs(s.mean - x) < 4:
                found = True
                s.values.append(x)
                s.n += 1
                old_m = s.mean
                s.mean = old_m + ((x - old_m) / s.n) 
        
        if found:
            self.verified = True

        if not found:
            # new segment
            segment = Segment(x)
            self.segments.append(segment)
            self.verified = False


    def equals(self, pattern2):

        # Kolmogorov–Smirnov test

        x = self.values
        n1 = self.n

        y = pattern2.values
        n2 = pattern2.n

        c_a = math.sqrt( - math.log(self.alpha/2) / 2)
        statistic = ks_2samp(x,y)[0]
        critical_value = c_a * math.sqrt( (n1 + n2) / (n1*n2))

        return statistic <= critical_value