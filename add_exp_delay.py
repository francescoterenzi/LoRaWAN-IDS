import pickle
from random import random, randint, seed, choices
from classes import Packet
from tqdm import tqdm
import numpy as np
from matplotlib import pyplot as plt

EXP_RATE = 0.03
SHOW_PLOTS = True


def exp_generator(exp_rate):
    while True:
        yield from np.random.exponential(1/exp_rate, size=(10**5,))


def add_exp_delay(packets, exp_rate):
    assert(exp_rate>0)

    # total delay of all the packets, in seconds
    exp_total_delay = 0
    # number of exponential arrival not used. An exponential arrival is not used
    # if it arrives before the original interarrival time of the packet
    exp_total_notused = 0

    devs = set([p.dev_eui for p in packets])  #set of all devices
    
    for dev in tqdm(devs, desc="Adding exponential delay to packets"):
        packets_dev = [p for p in packets if p.dev_eui == dev]
        
        if SHOW_PLOTS:
            plt.figure(1)
            plt.title("Interarrival times - Before exp delay")
            plt.hist([packets_dev[i].t-packets_dev[i-1].t for i in range(1, len(packets_dev))], bins=25)

        # init exponential interarrival times generator
        exp_gen = exp_generator(exp_rate)

        # modify packet arrival times
        t_exp = packets_dev[0].t
        for p in packets_dev[1:]:
            t_exp += next(exp_gen)
            while p.t > t_exp:
                # exponential arrival not used, it is before the original interarrival
                exp_total_notused += 1
                t_exp += next(exp_gen)
            # update stat
            exp_total_delay += t_exp - p.t
            # modify packet time
            p.t = t_exp

        if SHOW_PLOTS:
            plt.figure(2)
            plt.title("Interarrival times - After exp delay")
            plt.hist([packets_dev[i].t-packets_dev[i-1].t for i in range(1, len(packets_dev))], bins=25)
            plt.show()

    # print stats
    print(f"--- Exponential delay stats:")
    print(f"---    Average packet delay per packet: {exp_total_delay/len(packets):.2f} (s)")
    print(f"---    Average exponential arrival not used per packet: {exp_total_notused/len(packets)}")

    return packets


if __name__ == '__main__':
    # Load packets
    packets = pickle.load(open("synth_traffic.pickle", "rb"))
    packets = pickle.load(open(f"synth_traffic_delay_{EXP_RATE}.pickle", "rb"))

    # Add exp delay
    packets_delay = add_exp_delay(packets, EXP_RATE)

    # Save packets
    pickle.dump(packets_delay, open(f"synth_traffic_delay_{EXP_RATE}.pickle", "wb"))


