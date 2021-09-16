# check is the current dev address belongs to a new device
def debug_new_dev(devaddr):
    count = devaddr.split("_")[1]
    if int(count) >= 1:
        return "[NEW DEV ERROR] " + devaddr + " is not a new dev"
    else:
        return "[NEW DEV] " + devaddr + " is a new device"


# check if the two dev addresses belong to the same deveui
def debug_duplicate(devaddr1, devaddr2):
    deveui1 = devaddr1.split("_")[0]
    deveui2 = devaddr2.split("_")[0]
    
    seq1 = int(devaddr1.split("_")[1])
    seq2 = int(devaddr2.split("_")[1])

    if deveui1 != deveui2:
        return "[DUPLICATE ERROR] " + devaddr1 + " and" + devaddr2 + " don't belong to the same dev"
    elif abs(seq1 - seq2) > 1:    
        return "[DUPLICATE MISSING] " + devaddr1 + " and " + devaddr2 + " are not consecutive."
    else:
        return "[DUPLICATE] " + devaddr2 + " and " + devaddr1 + " belong to the same dev"

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