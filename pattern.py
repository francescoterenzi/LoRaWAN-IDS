from distribution import Distribution
import math

class Pattern:

    percentage_speed = 10

    def __init__(self, devaddr, timestamp):
        self.devaddr = devaddr
        self.timestamp = timestamp
        self.distribution = Distribution()
        self.quality_score = 0


    def update(self, timestamp):

        old_t = self.timestamp 
        new_t = timestamp
        
        x = new_t - old_t
        self.distribution.update(x)

        self.timestamp = new_t
        self.quality_score = self.__calculate_quality_score()


    def merge(self, pattern):

        new_devaddr = pattern.devaddr
        new_timestamp = pattern.timestamp

        self.devaddr = new_devaddr
        self.timestamp = new_timestamp
        self.distribution.merge(pattern.distribution)


    def equals(self, pattern2):

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
        
        return z_test <= 4
    

    def get_quality_score(self):
        return self.quality_score


    def __calculate_quality_score(self):
        count = self.distribution.n
        quality_score = count / (count + self.percentage_speed)
        return quality_score