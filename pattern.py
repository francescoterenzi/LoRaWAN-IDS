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
        self.n = 0
        self.m = 0
        self.quality_score = 0
        self.section = section
        self.alpha = 0.001


    def update(self, timestamp):

        old_t = self.timestamp 
        new_t = timestamp
        
        x = new_t - old_t
        self.values.append(x)
        self.n += 1

        if self.n > 1:
            delta = x - self.m
            self.m += delta / (self.n - 1)

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