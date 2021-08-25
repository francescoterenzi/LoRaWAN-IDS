from os import scandir
import math
import pickle
import time


def init(packets):
    sections = []
    mtypes = []
    join_requests = []

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

    return sections, mtypes, join_requests


def init_pattern(patterns, elem):
    patterns[elem.dev_addr] = { 
        "timestamps" : [],
        "interarrivals": [],
        "mean" : 0,
        "reliability" : 0
    }


def add_timestamp(patterns, elem):
    patterns[elem.dev_addr]["timestamps"].append(math.trunc(elem.t))


def get_mean(patterns, elem):
    return patterns[elem]["mean"]


def get_means(patterns):
    means = {}
    for elem in patterns:
        means[elem] = patterns[elem]["mean"]
    return means        


def update_means(patterns):            
    for dev_addr in patterns:
        interarrivals = patterns[dev_addr]["interarrivals"]
        if len(interarrivals) > 1:
            patterns[dev_addr]["mean"] = math.trunc(sum(interarrivals) / len(interarrivals))
        else:
            patterns[dev_addr]["mean"] = 0


def update_realiabilities(patterns):            
    for dev_addr in patterns:
        timestamps = patterns[dev_addr]["timestamps"]
        patterns[dev_addr]["reliability"] = len(timestamps)


def update_interarrivals(patterns):
    for dev_addr in patterns:        
        timestamps = patterns[dev_addr]["timestamps"]

        if len(timestamps) > 1:
            interarrivals = []
            for i in range(1, len(timestamps)):
                x = timestamps[i] - timestamps[i-1]
                interarrivals.append(x)
            patterns[dev_addr]["interarrivals"] = interarrivals


def calculate_reliability_score(patterns):
    realibilities = {
        "Low" : 0,
        "Medium" : 0,
        "High" : 0
    }
    realiability_score = 0
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
    return realiability_score


def update_patterns(patterns):
    update_interarrivals(patterns)
    update_means(patterns)
    update_realiabilities(patterns)


def statistics(packets, label):

    # PRIMO STEP
    # Elaboriamo una serie di dati fondamentali
    sections, mtypes, join_requests = init(packets)

    # SECONDO STEP
    # accendere il nostro IDS e lasciarlo così non è sufficiente.
    # abbiamo bisogno di una buona base da cui partire:
    # numero di DevAddr sufficientemente alto, e con un pattern ben definito

    patterns = {}
    index = 0
    realiability_score = 1
    realiability_threshold = 0
    
    while (realiability_score < realiability_threshold):
        
        current_section = sections[index]        

        for elem in current_section:
            if elem.dev_addr not in patterns:
                init_pattern(patterns, elem)
            add_timestamp(patterns, elem)

        update_patterns(patterns)    

        realiability_score = calculate_reliability_score(patterns)

        index += 1   

    print()
    print(str(index + 1) + " sections analyzed")
    print(">> Total Dev Addr: " + str(len(patterns)), )
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
        new_devaddrs = {}
        analyzed = []
        current_devaddr = set([elem.dev_addr for elem in section]) 

        for elem in section:
            devaddr = elem.dev_addr
            if devaddr not in patterns:
                # C'è un nuovo DevAddr, ora dobbiamo capire se è di un nuovo device
                new_devaddrs[devaddr] = 1
                init_pattern(patterns, elem)
                add_timestamp(patterns, elem)
                update_patterns(patterns)
                #print(patterns)
                #time.sleep(3)
            else:
                # già inserito nel pattern
                if devaddr in new_devaddrs:
                    # così abbiamo la conferma che è un Dev Addr che esiste solo in questa
                    # sezione. Ma ora abbiamo almeno due pacchetti -> inter arrival
                    add_timestamp(patterns, elem)
                    update_patterns(patterns)
                    new_devaddrs[devaddr] += 1
                    
                    if devaddr not in analyzed:  
                        all_means = get_means(patterns)
                        devaddr_mean = get_mean(patterns, devaddr)

                        for elem in all_means:
                            mean = all_means[elem]
                            error = 0
                            if mean > 0:
                                if devaddr != elem and elem not in current_devaddr:
                                    if devaddr_mean >= mean - error and devaddr_mean <= mean + error:
                                        print(devaddr, elem)
                                        print(devaddr_mean, mean)
                                        print()
                                        #time.sleep(3)
                        analyzed.append(devaddr)

def main():

    # loading the datasets
    synth_packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    #torrecanavese_packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))

    # printing some statistics
    statistics(synth_packets, "Synthetic dataset")
    #statistics(torrecanavese_packets, "Real dataset")


if __name__ == "__main__":
    main()
