class Distribution:

    def __init__(self):
        self.m = 0
        self.M2 = 0
        self.s = 0
        self.lowest = 0
        self.highest = 0
        self.range = 0
        self.n = 0


    def update(self, x):

        self.n += 1

        if self.lowest > x:
            self.lowest = x
        
        if self.highest < x:
            self.highest = x

        if self.lowest == x or self.highest == x:
            self.range = self.highest - self.lowest

        if self.n > 1:
            delta = x - self.m
            self.m += delta / (self.n - 1)
            self.M2 += delta * (x - self.m)
            self.s = self.M2 / (self.n - 1)
    

    def merge(self, distribution2):
        
        n1 = self.n        
        m1 = self.m
        M2_1 = self.M2
        
        n2 = distribution2.n
        m2 = distribution2.m
        M2_2 = distribution2.M2

        delta = m2 - m1
        new_n = n1 + n2
        delta = m2 - m1

        new_mean = m1 + delta * (n2/new_n)
        new_M2 = M2_1 + M2_2 + (delta ** 2) * (n1 * n2/new_n)
        new_s = new_M2 / (new_n - 1)

        self.n = new_n
        self.m = new_mean
        self.M2 = new_M2
        self.s = new_s
        