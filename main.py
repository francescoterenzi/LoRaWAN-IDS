from os import scandir
import pickle
from pivot import PIVOT
from generator import generate_synt_traffic
import time
from pivot import PIVOT
from tqdm import tqdm

# global parameters
N = 150
exp_rate = 0 

def main():

    # generating the dataset
    print("Generating the dataset:")
    generate_synt_traffic(N, exp_rate)

    # loading the dataset
    print("Loading the dataset:")
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))

    # new instance of PIVOT
    pivot = PIVOT()

    # PIVOT on listening
    print("Analyzing the traffic stream:")
    for p in packets:
        pivot.read_packet(p)

if __name__ == "__main__":
    main()
