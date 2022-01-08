from os import device_encoding
import pickle
from pivot import PIVOT
from generator import Generator
from matplotlib import pyplot as plt

# global parameters
N = 100
P = 5
Jmin = 20
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

    for N in range(50, 205, 5):
        # creating  new dataset 
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

        
        x_axis.append(N)
        y_axis.append(debug.recall())
    
    print(x_axis)
    print(y_axis)

    print("Lower value: ", min(y_axis))
    print("Higher value: ", max(y_axis))
    print("aritmetic mean: ", sum(y_axis) / len(y_axis))

    # fig, ax = plt.subplots()
    plt.hist(y_axis)
    plt.xlabel('Number of devices')
    plt.ylabel('Recall')
    plt.show()


if __name__ == "__main__":
    main()