from os import scandir
import pickle
import time
from ids import IDS


def real_dataset_statistics(packets):
    tot_dev_eui = []
    sections = []
    current_section = []

    for p in packets:
        dev_eui = p.dev_eui
        if p.mtype == "Join Request":
            sections.append(set(current_section))
            current_section = []
        else:
            if dev_eui not in tot_dev_eui:
                tot_dev_eui.append(dev_eui)
                current_section.append(dev_eui)
    sections.append(set(current_section))
    
    return sections, tot_dev_eui


def main():

    #label = "Synth network"
    #label = "Torre Canavese"
    label = "Synth network v2"

    # carichiamo il dataset
    #packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    #packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))
    packets =  pickle.load(open("synth_traffic.pickle", "rb"))



    # accendiamo il nostro IDS
    ids = IDS(label) 

    # IDS in ascolto
    for p in packets:
        ids.read_packet(p)
        
    # conclusa l'analisi, stampiamo alcune statistiche generali
    ids.statistics()     


if __name__ == "__main__":

    start_time = time.time()
    main()
    print("--- %s seconds ---\n\n" % (time.time() - start_time))
