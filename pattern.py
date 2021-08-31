from time import sleep
from distribution import Distribution
import math
import numpy as np
from scipy.stats import ks_2samp

class Pattern:

    percentage_speed = 10

    def __init__(self, devaddr, timestamp, section):
        self.devaddr = devaddr
        self.timestamp = timestamp
        self.values = []
        #self.distribution = Distribution()
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
            #self.M2 += delta * (x - self.m)
            #self.s = self.M2 / (self.n - 1)

        #self.distribution.update(x)

        self.timestamp = new_t

        #count = self.distribution.n
        #self.quality_score = count / (count + self.percentage_speed)

    '''
    def merge(self, pattern):

        new_devaddr = pattern.devaddr
        new_timestamp = pattern.timestamp

        self.devaddr = new_devaddr
        self.timestamp = new_timestamp
        self.distribution.merge(pattern.distribution)
    '''

    def equals(self, pattern2):
        
        '''
        m1 = self.distribution.m
        s1 = self.distribution.s
        n1 = self.distribution.n

        m2 =  pattern2.distribution.m
        s2 = pattern2.distribution.s
        n2 = pattern2.distribution.n
        
        elem_1 = (math.sqrt(s1) / math.sqrt(n1)) ** 2
        elem_2 = (math.sqrt(s2) / math.sqrt(n2)) ** 2

        z_test = abs(m2 - m1) / math.sqrt(elem_1 + elem_2)
        
        #error = 0.7 
        #margin = 3.5

        #return abs(m2 - m1) <= error and abs(std_S_2 - std_S_1) <= margin
        
        return z_test <= 5.5
        '''

        #x = self.distribution.values
        x = self.values
        n1 = self.n

        #y = pattern2.distribution.values
        y = pattern2.values
        n2 = pattern2.n

        c_a = math.sqrt( - math.log(self.alpha/2) / 2)
        statistic = ks_2samp(x,y)[0]
        critical_value = c_a * math.sqrt( (n1 + n2) / (n1*n2))

        #print("n1: " + str(n1) + " n2: " + str(n2))
        #print("statistic: " + str(statistic) + " critical value: " + str(critical_value))
        #print()
        #sleep(1)

        return statistic <= critical_value