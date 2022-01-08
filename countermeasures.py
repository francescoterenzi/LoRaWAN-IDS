import pickle
import os
from pivot import PIVOT
from add_exp_delay import new_exp_traffic
from generator import Generator

# global parameters
N = 100
P = 4
Jmin = 20
Jmax = 300
Emin = 0.01
Emax = 2       

e = 4
 
def main():

    # initializing the generator
    generator = Generator()

    # creating the original dataset 
    print("Generating the dataset:")
    generator.new_traffic_flow(N, P, Jmin, Jmax, Emin, Emax)

    # loading the original dataset
    print("Loading the dataset:")
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))

    # new instance of PIVOT
    pivot = PIVOT(e)

    # PIVOT on listening
    print("Analyzing the original traffic stream:")
    for p in packets:
        pivot.read_packet(p)
    
    # printing metrics
    pivot.print_metrics()

    exp_rates = [0.01, 0.05, 0.1]
    
    for exp in exp_rates:
        # resetting PIVOT
        pivot.reset()

        if not os.path.isfile(f"synth_traffic_delay_{exp}.pickle"):
            new_exp_traffic(exp)

        # loading the dealyed dataset
        print("Loading the modified dataset:")
        packets =  pickle.load(open(f"synth_traffic_delay_{exp}.pickle", "rb"))

        # PIVOT on listening
        print("Analyzing the modified traffic stream, exp_rate = ", exp)
        for p in packets:
            pivot.read_packet(p)
    
        # printing metrics
        pivot.print_metrics()

    

if __name__ == "__main__":
    main()