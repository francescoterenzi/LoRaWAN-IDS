from os import device_encoding
import pickle
from pivot import PIVOT
from generator import Generator
from matplotlib import pyplot as plt
import numpy as np

# global parameters
N = 100
P = 5
Jmin = 10
Jmax = 300
Emin = 0.01
Emax = 2       
exp_rate = 0.05

e = 4

def main():

    # initializing the generator
    generator = Generator()

    x_axis = []
    y_axis = []

    for N in range(50, 200, 5):
        # creating a new dataset 
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
        debug = pivot.get_debug()

        #print(debug.get_metrics())
        #print(debug.precision())
        #print(debug.recall())

        x_axis.append(N)
        y_axis.append(debug.accuracy())

    fig, ax = plt.subplots()
    ax.plot(x_axis, y_axis)
    ax.set(xlabel='Length of P', ylabel='Recall')
            
    #fig.savefig("test.png")
    plt.ylim([0, 1])
    plt.show()

    
    '''
    # resetting PIVOT
    pivot.reset()

    new_exp_traffic(exp_rate)

    # loading the dealyed dataset
    print("Loading the modified dataset:")
    packets =  pickle.load(open(f"synth_traffic_delay_{exp_rate}.pickle", "rb"))

    # PIVOT on listening
    print("Analyzing the modified traffic stream:")
    for p in packets:
        pivot.read_packet(p)
 
    # printing metrics
    pivot.print_metrics()
    pivot.print_debug()
    '''

if __name__ == "__main__":
    main()