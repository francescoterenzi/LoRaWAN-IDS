from os import scandir
import math
import pickle


def statistics(packets, label):

    # PRIMO STEP
    # Elaboriamo una serie di dati fondamentali, tra cui le sezioni

    mtypes = []
    sections = []
    join_requests = []

    # find the sections
    current_section = []
    for p in packets:
        if p.mtype not in mtypes:
            mtypes.append(p.mtype)
        if (p.mtype == "Join Request"):
            sections.append(current_section)
            join_requests.append(p)
            current_section = []
        else:
            current_section.append(p)
    sections.append(current_section)

    # SECONDO STEP
    # accendere il nostro IDS e lasciarlo così non è sufficiente.
    # abbiamo bisogno di una buona base da cui partire:
    # numero di DevAddr sufficientemente alto, e con un pattern ben definito

    patterns = {}
    index = 0
    realiability_score = 0
    realiability_threshold = 200
    realibilities = {
        "Low" : 0,
        "Medium" : 0,
        "High" : 0
    }
    
    while (realiability_score < realiability_threshold):
        
        current_section = sections[index]        
        current_devaddrs = set([ elem.dev_addr + "" for elem in current_section ])
        
        #devaddrs.append(current_devaddrs)
        new_devices = 0

        for elem in current_devaddrs:
            
            if elem not in patterns:
                new_devices += 1

            patterns[elem] = { 
                "timestamps" : [],
                "interarrivals": [],
                "mean" : 0,
                "reliability" : 0
            }

        for elem in current_section:
            patterns[elem.dev_addr]["timestamps"].append(math.trunc(elem.t))

        for dev_addr in patterns:
            timestamps = patterns[dev_addr]["timestamps"]

            if len(timestamps) > 1:
                inter_arrivals = []
                for i in range(1, len(timestamps)):
                    x = timestamps[i] - timestamps[i-1]
                    inter_arrivals.append(x)

                patterns[dev_addr]["interarrvial"] = inter_arrivals
        
        for dev_addr in patterns:
            timestamps = patterns[dev_addr]["timestamps"]
            patterns[dev_addr]["mean"] = math.trunc(sum(timestamps) / len(timestamps))
            patterns[dev_addr]["reliability"] = len(timestamps)

        for dev_addr in patterns:
            reliability = patterns[dev_addr]["reliability"]

            if reliability <= 2:
                realibilities["Low"] += 1
            elif reliability > 2 and reliability <= 10:
                realibilities["Medium"] += 1
            else:
                realibilities["High"] += 1 
    
        realiability_score = (0.2 * realibilities["Low"] + \
                              0.4 * realibilities["Medium"] + \
                              0.4 * realibilities["High"] ) // len(realibilities)
        
        index += 1   
    
    print()
    print(str(index + 1) + " sections analyzed")
    print(">> Total Dev Addr: " + str(len(patterns)), )
    #print("\r>> New devices: " + str(new_devices))
    for key in realibilities:
        print(">> Num. of DevAddr with " + key + " score: " + str(realibilities[key]),  )
    print(">> Reliability score: ", realiability_score)
    print()


    # final data
    num_of_packets = len(packets)
    num_of_data = len([j for i in sections for j in i])
    num_of_sections = len(sections)
    num_of_joins = len(join_requests)

    # print statistics
    print(30 * "=")
    print()
    print(label.upper())

    print()

    print("Num. of overall packets: " + str(num_of_packets))
    print("Num. of Data packets: " + str(num_of_data))
    print("Num. of Join Requests: " + str(num_of_joins))
    print("Num. of sections: " + str(num_of_sections))
    print("mtypes: ", mtypes)
    
    print()
    print(30 * "=" + "\n\n")


    # TERZO STEP
    # Abbiamo raccolto una sufficiente quantità di DevAddr, e la maggior parte di loro
    # ha un pattern ben definito, quindi si analizzano i nuovi DevAddr e si cerca di capire
    # se potenzialmente sono provenienti da nuovi o da vecchi devices.

    for section in sections[index:]:

        new_devaddrs = 0
        current_devaddrs = set([ elem.dev_addr + "" for elem in section ])

        for elem in current_devaddrs:
            if elem not in patterns:
                print("New Dev Addr found!")
                new_devaddrs += 1

def main():

    # loading the datasets
    synth_packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    torrecanavese_packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))

    # printing some statistics
    #statistics(synth_packets, "Synthetic dataset")
    #statistics(torrecanavese_packets, "Real dataset")


if __name__ == "__main__":
    main()
