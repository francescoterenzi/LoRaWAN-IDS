from os import scandir
import pickle
from synth_traffic import generate_synt_traffic
import time
from ids import IDS
from ids_v2 import IDS_V2
from tqdm import tqdm

N = 150     # num of devices

def main():

    # generating the dataset
    print("Generating the dataset:")
    generate_synt_traffic(400)
    print("\n\n", end='')

    # loading the dataset
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))

    '''
    # new instance of our IDS
    ids = IDS()

    # IDS on listening
    start_time = time.time()
    print("Analyzing the dataset:")
    for i in tqdm(range(len(packets))):
        ids.read_packet(packets[i])
    print("--- %s seconds ---\n\n" % (time.time() - start_time))   
    '''

    # new instance of our IDS
    ids_v2 = IDS_V2()

    # IDS on listening
    start_time = time.time()
    print("Analyzing the dataset:")
    for i in tqdm(range(len(packets))):
        ids_v2.read_packet(packets[i])
    print("--- %s seconds ---\n\n" % (time.time() - start_time))   


if __name__ == "__main__":
    main()
