import pickle
from pivot import PIVOT
from generator import Generator
from add_exp_delay import new_exp_traffic
from pivot import PIVOT

# global parameters
N = 150
exp_rate = 0.1 

def main():

    # initializing the generator
    generator = Generator()

    # creating a new dataset
    print("Generating the dataset:")
    generator.new_traffic_flow(N)

    # loading the original dataset
    print("Loading the dataset:")
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))

    # new instance of PIVOT
    pivot = PIVOT()

    # PIVOT on listening
    print("Analyzing the original traffic stream:")
    for p in packets:
        pivot.read_packet(p)
    
    # printing metrics
    pivot.print_metrics()

    # resetting PIVOT
    pivot.reset()

    # new_exp_traffic(exp_rate)

    # loading the dealyed dataset
    print("Loading the modified dataset:")
    packets =  pickle.load(open(f"synth_traffic_delay_{exp_rate}.pickle", "rb"))

    # PIVOT on listening
    print("Analyzing the modified traffic stream:")
    for p in packets:
        pivot.read_packet(p)
 
    # printing metrics
    pivot.print_metrics()

if __name__ == "__main__":
    main()