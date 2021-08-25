import math

class IDS:
     
    patterns = {}
    to_analyze = {}
    # precision_score = 0

    def __init__(self):
        pass

    # private methods
    def __update_means(self):            
        for dev_addr in self.patterns:
            interarrivals = self.patterns[dev_addr]["interarrivals"]
            if len(interarrivals) > 1:
                self.patterns[dev_addr]["mean"] = math.trunc(sum(interarrivals) / len(interarrivals))
            else:
                self.patterns[dev_addr]["mean"] = 0


    def __update_realiabilities(self):            
        for dev_addr in self.patterns:
            timestamps = self.patterns[dev_addr]["timestamps"]
            self.patterns[dev_addr]["reliability"] = len(timestamps)


    def __update_interarrivals(self):
        for dev_addr in self.patterns:        
            timestamps = self.patterns[dev_addr]["timestamps"]

            if len(timestamps) > 1:
                interarrivals = []
                for i in range(1, len(timestamps)):
                    x = timestamps[i] - timestamps[i-1]
                    interarrivals.append(x)
                self.patterns[dev_addr]["interarrivals"] = interarrivals


    def __quality_score(self, n):
        return (n / (n + 10))


    def init_pattern(self, elem):
        self.patterns[elem.dev_addr] = {
            "count" : 1, 
            "timestamps" : [elem.t],
            "interarrivals": [],
            "mean" : 0,
            "quality_score": 0
        }


    def add_timestamp(self, elem):
        self.patterns[elem.dev_addr]["timestamps"].append(math.trunc(elem.t))
        self.patterns[elem.dev_addr]["count"] += 1
        self.patterns[elem.dev_addr]["quality_score"] = self.__quality_score(self.patterns[elem.dev_addr]["count"])


    def get_mean(self, elem):
        return self.patterns[elem]["mean"]


    def get_means(self):
        means = {}
        for elem in self.patterns:
            means[elem] = self.patterns[elem]["mean"]
        return means        


    def calculate_reliability_score(self):
        realibilities = {
            "Low" : 0,
            "Medium" : 0,
            "High" : 0
        }
        realiability_score = 0
        for dev_addr in self.patterns:
            reliability = self.patterns[dev_addr]["reliability"]

            if reliability <= 2:
                realibilities["Low"] += 1
            elif reliability > 2 and reliability <= 10:
                realibilities["Medium"] += 1
            else:
                realibilities["High"] += 1 

            realiability_score = (0.2 * realibilities["Low"] + \
                                    0.4 * realibilities["Medium"] + \
                                    0.4 * realibilities["High"] ) // len(realibilities)
        return realiability_score

    def get_patterns(self):
        return self.patterns

    def set_pattern(self, devaddr, dict):
        self.patterns[devaddr] = dict

    def update_patterns(self):
        self.__update_interarrivals()
        self.__update_means()
        self.__update_realiabilities()