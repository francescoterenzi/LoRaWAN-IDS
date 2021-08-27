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

    # nome della rete
    label = "Synth network"
    #label = "Torre Canavese"


    # carichiamo il dataset
    packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    #packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))

    # elaboriamo a priori i dati per confrontarli con i risulati del nostro IDS
    sections, real_deveui = real_dataset_statistics(packets)    
    num_of_devices = len(real_deveui)

    # accendiamo il nostro IDS
    ids = IDS(label)


    # IDS in ascolto
    current_num_of_devices = 0
    for p in packets:

        mtype = ids.read_packet(p)
        
        if mtype == "Join Request":
            current_section, last_section_packets, patterns = ids.last_section_statistics()

            index = current_section - 2
            current_num_of_devices += len(sections[index])

            real_devices_sect = len(sections[index])
            real_devices_netw = str(current_num_of_devices) + "/" + str(num_of_devices)

            ids_devices_netw = str(patterns) + "/" + str(num_of_devices)

            
            # stuff to print
            #print("ANALYSIS OF SECTION N° " + str(current_section - 1))
            '''           
            print()
            print(">> Total packets of section: ", last_section_packets)
            print()
            print(">> [REAL] Current devices in the network: " + real_devices_netw)
            print(">> [IDS] Current devices in the network: " + ids_devices_netw)
            print()
            print(">> [REAL] New devices in this section: ", real_devices_sect)
            print(">> [IDS]  New devices in this section: to be defined: ")
            print("\n\n\n", end='')
            '''
            #time.sleep(3)
        
        else:
            ids.elaborate_pattern(p)


    current_section, last_section_packets, patterns = ids.last_section_statistics()

    index = current_section - 2
    current_num_of_devices += len(sections[index])

    real_devices_netw = str(current_num_of_devices) + "/" + str(num_of_devices)
    ids_devices_netw = str(patterns) + "/" + str(num_of_devices)

    #print(">> [REAL] Current devices in the network: " + real_devices_netw)
    #print(">> [IDS] Current devices in the network: " + ids_devices_netw)

    # conclusa l'analisi, stampiamo alcune statistiche generali
    ids.statistics()     

if __name__ == "__main__":
    main()
