class Segment:

    def __init__(self, value, index):
        #self.values = [value]
        self.n = 1
        self.index = index
        self.mean = value

    def belongs_to(self, pattern):
        for s in pattern.segments:
            if abs(s.mean - self.mean) < 5:
                return True
        return False  
    
    def update(self, value):
        #self.values.append(value)
        self.n += 1
        old_m = self.mean
        self.mean = old_m + ((value - old_m) / self.n)