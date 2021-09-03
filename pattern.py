from time import sleep
import math
import numpy as np
from scipy.stats import ks_2samp

class Pattern:

    percentage_speed = 10

    def __init__(self, devaddr, timestamp, section):
        self.devaddr = devaddr
        self.timestamp = timestamp
        self.values = []
        self.segments = []
        self.n = 0
        self.m = 0
        self.quality_score = 0
        self.section = section
        self.alpha = 0.001


    def update(self, timestamp):

        old_t = self.timestamp 
        new_t = timestamp
        
        x = new_t - old_t
        
        for s in self.segments:
            if s.mean == 0:
                s.mean = x
            elif abs(s.mean - x) < 10:
                s.values.append(x)
                s.n += 1

                if s.n > 1:
                    delta = x - s.mean
                    s.mean += delta / (s.n - 1)

        self.timestamp = new_t


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