from os import scandir
import pickle
from pivot import PIVOT
from synth_traffic import generate_synt_traffic
import time
from pivot import PIVOT
from tqdm import tqdm

N = 150     # num of devices

def main():

    # generating the dataset
    print("Generating the dataset:")
    generate_synt_traffic(400)
    print("\n\n", end='')

    # loading the dataset
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))

    # new instance of our IDS
    pivot = PIVOT()

    # IDS on listening
    start_time = time.time()
    print("Analyzing the dataset:")
    for i in tqdm(range(len(packets))):
        pivot.read_packet(packets[i])
    print("--- %s seconds ---\n\n" % (time.time() - start_time))

    # qui dobbiamo confontare i risultati del nostro IDS con quelli reali
    # e mostrare la % di DevAddress beccati

    # qui dobbiamo modifiare il dataset

    # qui dobbiamo far ripartire il nostro IDS

    # qui dobbiamo confrontare i risultati del nostro IDS con quelli reali
    # e mostrare che la % di DevAddress beccati cala drasticamente   


if __name__ == "__main__":
    main()
