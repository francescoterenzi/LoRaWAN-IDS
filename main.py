from os import scandir
import pickle
import time
from ids import IDS


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
    

    # accendiamo il nostro IDS
    ids = IDS() 

    # IDS in ascolto
    for p in packets:
        ids.read_packet(p)
        
    # conclusa l'analisi, stampiamo alcune statistiche generali
    print_statistics(label, ids)     


if __name__ == "__main__":

    start_time = time.time()
    main()
    print("--- %s seconds ---\n\n" % (time.time() - start_time))
