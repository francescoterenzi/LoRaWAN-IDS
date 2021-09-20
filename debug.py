class Debug:

    def __init__(self, filename):
        self.filename = filename
        self.f = open(filename, "w")
        self.f.close()


    # check is the current dev address belongs to a new device
    def new_dev(self, devaddr):
        to_write = ""
        count = devaddr.split("_")[1]
        
        if int(count) >= 1:
            to_write =  "[NEW DEV ERROR] " + devaddr + " is not a new dev"
        else:
            to_write =  "[NEW DEV] " + devaddr + " is a new device"
        
        self.f = open(self.filename, "a")
        self.f.write(to_write + "\n")
        self.f .close()


    # check if the two dev addresses belong to the same deveui
    def duplicate(self, devaddr1, devaddr2):
        to_write = ""
        deveui1 = devaddr1.split("_")[0]
        deveui2 = devaddr2.split("_")[0]
        
        seq1 = int(devaddr1.split("_")[1])
        seq2 = int(devaddr2.split("_")[1])

        if deveui1 != deveui2:
            to_write =  "[DUPLICATE ERROR] " + devaddr1 + " and" + devaddr2 + " don't belong to the same dev"
        elif abs(seq1 - seq2) > 1:    
            to_write =  "[DUPLICATE MISSING] " + devaddr1 + " and " + devaddr2 + " are not consecutive."
        else:
            to_write = "[DUPLICATE] " + devaddr2 + " and " + devaddr1 + " belong to the same dev"

        self.f = open(self.filename, "a")
        self.f.write(to_write + "\n")
        self.f .close()

'''
def debug_quar2new_dev(self, devaddr):
    self.f = open("result.txt", "a")
    count = devaddr.split("_")[1]
    if int(count) >= 1:
        self.f.write("[QUAR - >NEW DEV ERROR] " + devaddr + " is not a new dev\n")
    else:
        self.f.write("[QUAR -> NEW DEV] " + devaddr + " is a new device\n")
    self.f.close()
'''