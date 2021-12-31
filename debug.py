class Debug:

    def __init__(self):
        self.false_positive = 0
        self.false_negative = 0
        self.true_positive = 0
        self.true_negative = 0

    def check_match(self, devaddr1, devaddr2):
        deveui1 = devaddr1.split("_")[0]
        deveui2 = devaddr2.split("_")[0]

        if deveui1 == deveui2:
            self.true_positive += 1
        else:
            self.false_positive += 1

    def update_false_negative(self, unconfirmed):
        for elem in unconfirmed:
            if int(elem.split("_")[1]) > 0:
                self.false_negative += 1


    def check_new_device(self, devaddr):
        temp = devaddr.split("_")[1]
        if int(temp) > 0:
            self.false_negative += 1
        else:
            self.true_negative += 1

    def precision(self):
        return self.true_positive / (self.true_positive + self.false_positive)
    
    def recall(self):
        return self.true_positive / (self.true_positive + self.false_negative)

    
    def accuracy(self):
        return (self.true_positive + self.true_negative) / (self.true_positive + self.true_negative + self.false_positive + self.false_negative)

    def get_metrics(self):
        return { 
            "FN" : self.false_negative,
            "TN" : self.true_negative,
            "FP" : self.false_positive,
            "TP" : self.true_positive
        }
