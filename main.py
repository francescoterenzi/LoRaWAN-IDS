from os import scandir
import math
import pickle
from ids import IDS

def init(packets):
    sections = []
    current_section = []
    for p in packets:
        if (p.mtype == "Join Request"):
            sections.append(current_section)
            current_section = []
        else:
            current_section.append(p)
    sections.append(current_section)

    return sections, len(sections) - 1


def quality_score(n):
    return (n / (n + 10))


def init_pattern(patterns, elem):
    patterns[elem.dev_addr] = {
        "count" : 1, 
        "timestamps" : [elem.t],
        "interarrivals": [],
        "mean" : 0,
        "quality_score": 0
    }


def add_timestamp(patterns, elem):
    patterns[elem.dev_addr]["timestamps"].append(math.trunc(elem.t))
    patterns[elem.dev_addr]["count"] += 1
    patterns[elem.dev_addr]["quality_score"] = quality_score(patterns[elem.dev_addr]["count"])


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
        if len(interarrivals) >= 1:
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


def main():

    # loading the datasets
    packets = pickle.load(open("synth_traffic.packets.devaddr", "rb"))
    label = "SYNTH DATA"
    
    #packets =  pickle.load(open("torrecanavese.packets.devaddr", "rb"))
    #label = "REAL DATA"

    # accenediamo il nostro IDS
    ids = IDS()

    # PRIMO STEP
    # Elaboriamo una serie di dati fondamentali
    sections, join_requests = init(packets)

    index = 0
    # è un ciclo iniziale di tuning: se le informazioni che abbiamo
    # in nostro possesso sono troppo poche allora andiamo avanti fino a quando
    # non raggiungiamo un reliability score idoneo
    # al momento questa parte la schippo, quindi pongo come threshold = 0    
    
    '''
    realiability_score = 1
    realiability_threshold = 0
    while (realiability_score < realiability_threshold):
        
        current_section = sections[index]        

        for elem in current_section:
            if elem.dev_addr not in patterns:
                init_pattern(patterns, elem)
            else:
                add_timestamp(patterns, elem)

        update_patterns(patterns)    

        realiability_score = calculate_reliability_score(patterns)

        index += 1 
    '''

    # final data
    num_of_packets = len(packets)
    num_of_data = len([j for i in sections for j in i])
    num_of_sections = len(sections)
    num_of_joins = join_requests

    # print statistics
    print(30 * "=")
    print()
    print(label.upper())

    print()

    print("Num. of overall packets: " + str(num_of_packets))
    print("Num. of Data packets: " + str(num_of_data))
    print("Num. of Join Requests: " + str(num_of_joins))
    print("Num. of sections: " + str(num_of_sections))
    print()
    print(30 * "=" + "\n\n")


    # Abbiamo raccolto una sufficiente quantità di DevAddr, e la maggior parte di loro
    # ha un pattern ben definito, quindi si analizzano i nuovi DevAddr e si cerca di capire
    # se potenzialmente sono provenienti da nuovi o da vecchi devices.
    
    to_analyze = {}
    tot_deveui = []
    count = 0
    tot_devices = 0
    for section in sections:
        
        count += 1
        new_devices = 0
        section_deveui = []
        for packet in section:
            
            devaddr = packet.dev_addr
            timestamp = packet.t

            deveui = devaddr.split("_")[0]
            temp = devaddr.split("_")[1]

            if deveui not in section_deveui:
                section_deveui.append(deveui)

            if deveui not in tot_deveui:
                tot_deveui.append(deveui)
                if temp == "0":
                    new_devices += 1

            if devaddr not in ids.get_patterns():
                if devaddr not in to_analyze:
                    init_pattern(to_analyze, packet)
                else:
                    add_timestamp(to_analyze, packet)
                    update_patterns(to_analyze)
               

                    current_devaddr_mean = get_mean(to_analyze, devaddr)
                    means = ids.get_means()

                    error = 0
                    duplicate = False
                    for elem in means:
                        m = means[elem]
                        if current_devaddr_mean >= m - error and current_devaddr_mean <= m + error:
                            suffix = devaddr.split("_")[1]
                            if int(suffix) == 0:
                                print(devaddr + " " + elem)
                                print(str(current_devaddr_mean) + " " + str(m))
                                print("There is an error!")
                                exit()
                            duplicate = True
                    
                    if not duplicate:
                        ids.set_pattern(devaddr, to_analyze[devaddr])
                        to_analyze.pop(devaddr)
                        

            else:
                ids.add_timestamp(packet)

            ids.update_patterns()
            
        tot_devices += new_devices        


        # stuff to print
        print("ANALYSIS OF SECTION N° " + str(count))
        if len(section) > 0:
            print(">> Total packets of section: " + str(len(section)))
            print(">> Percentage of new devices: {0:.0%}".format(new_devices / len(section_deveui)))
        else:
            print(">> No packets received")
        
        print(">> Total devices in the network: " + str(tot_devices))
        print(">> Patterns recognized by IDS: ", len(ids.get_patterns()))
        print(">> Patterns still to recognize: ", len(to_analyze))
        print()
        #time.sleep(3)


if __name__ == "__main__":
    main()
