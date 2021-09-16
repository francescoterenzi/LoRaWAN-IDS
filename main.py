from os import scandir
import pickle
import time
from ids import IDS
from ids_v2 import IDS_V2
from tqdm import tqdm


def print_statistics(label, ids):
    
    res, confirmed, unconfirmed, num_of_deveui = ids.get_statistics()

    num_of_packets = res["num_of_packets"]
    current_section = res["current_section"]
    num_of_err = res["num_of_err"]
    num_of_joins = current_section - 1
    num_of_data = num_of_packets - num_of_joins


    print(30 * "=")
    print()
    print(label.upper())

    print()

    print("Num. of overall packets: " + str(num_of_packets))
    print("Num. of Data packets: " + str(num_of_data))
    print("Num. of Join Requests: " + str(num_of_joins))
    print("Num. of sections: " + str(current_section))
    print("Num. of devices: " + str(confirmed))
    print("Num. of unique devices: " + str(num_of_deveui))
    print("Len. of unconfirmed pattern list: " + str(unconfirmed))
    print("Num. of errors: " + str(num_of_err))
    print()
    print(30 * "=" + "\n\n")


def main():

    #label = "Synth network"
    #label = "Torre Canavese"
    label = "Synth network v2"

    # carichiamo il dataset
    #packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    #packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))


    # accendiamo il nostro IDS V1
    ids = IDS()

    # IDS in ascolto
    start_time = time.time()
    for i in tqdm(range(len(packets))):
        ids.read_packet(packets[i])
    print("--- %s seconds ---\n\n" % (time.time() - start_time))
    

    # accendiamo il nostro IDS V2
    ids_v2 = IDS_V2() 
    
    # IDS in ascolto
    start_time = time.time()
    for i in tqdm(range(len(packets))):
        ids_v2.read_packet(packets[i])
    print("--- %s seconds ---\n\n" % (time.time() - start_time))
        
    # conclusa l'analisi, stampiamo alcune statistiche generali
    #print_statistics(label, ids)     


if __name__ == "__main__":
    main()
