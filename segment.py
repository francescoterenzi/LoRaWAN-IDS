class Segment:

    def __init__(self, value):
        self.values = [value]
        self.n = 1
        self.mean = value

    def belongs_to(self, pattern):
        for s in pattern.segments:
            if abs(s.mean - self.mean) < 5:
                return True
        return False  