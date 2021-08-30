import math

class Pattern:

    devaddr = ""
    count = 0
    timestamp = 0
    interarrival = 0
    M2 = 0
    variance = 0

    def __init__(self, devaddr, timestamp):
        self.devaddr = devaddr
        self.timestamp = timestamp


    def update(self, timestamp):

        t = self.timestamp
        m = self.interarrival
        n = self.count + 1
        M2 = self.M2
        S = self.variance
      
        new_t = math.trunc(timestamp)
        x = new_t - t

        if n > 1:
            delta = x - m
            m += delta / (n - 1)
            M2 += delta * (x - m)
            S = M2 / (n - 1)

        self.count = n
        self.timestamp = new_t
        self.interarrival = round(m, 4)
        self.M2 = M2
        self.variance = round(S, 4)


    def merge(self, pattern):

        new_devaddr = pattern.devaddr
        new_timestamp = pattern.timestamp

        count1 = self.count        
        mean1 = self.interarrival
        M2_1 = self.M2
        
        count2 = pattern.count
        mean2 = pattern.interarrival
        M2_2 = pattern.M2

        delta = mean2 - mean1
        new_count = count1 + count2
        delta = mean2 - mean1

        new_mean = mean1 + delta * (count2/new_count)
        new_M2 = M2_1 + M2_2 + (delta ** 2) * (count1 * count2/new_count)
        new_S = new_M2 / (new_count - 1)

        self.devaddr = new_devaddr
        self.count = new_count
        self.timestamp = new_timestamp
        self.interarrival = round(new_mean, 4)
        self.M2 = new_M2
        self.variance = round(new_S, 4)


    def equals(self, pattern2):

        m1 = self.interarrival
        S_1 = self.variance
        count1 = self.count

        m2 =  pattern2.interarrival
        S_2 = pattern2.variance
        count2 = pattern2.count
        
        dev_1 = (math.sqrt(S_1) / math.sqrt(count1)) ** 2
        dev_2 = (math.sqrt(S_2) / math.sqrt(count2)) ** 2

        z_test = abs(m2 - m1) / math.sqrt(dev_1 + dev_2)
        
        #error = 0.7 
        #margin = 3.5

        #return abs(m2 - m1) <= error and abs(std_S_2 - std_S_1) <= margin
        
        return z_test <= 4
    
    
    def get_count(self):
        return self.count