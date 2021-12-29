"""
Generates synthetic traffic of multiple devices following random patterns
"""
import pickle
from random import random, randint, seed, choices
from classes import Packet
from tqdm import tqdm
import numpy as np
from matplotlib import pyplot as plt


seed(42)  #reproducible

#N = 300             # number of devices
S = 50*24*3600     # number of seconds to generate packets
Emin = 0.01            # minimum absolute error in the interarrival time, in seconds
Emax = 2           # maximum absolute error in the interarrival time, in seconds
P = 3              # maximum length of a pattern
Jmin = 20           # minimum number of messages before a join
Jmax = 300          # maximum number of messages before a join
USE_LOED_DISTR = True       # use interarrival time distribution from LoED dataset
show_plot = False

if USE_LOED_DISTR:
    _cdf_X, _cdf_Y = pickle.load(open("LoED/interarrivals_X_cdf.pickle", "rb"))
    pdf_X, pdf_Y = [], []
    prev_y = _cdf_Y[0]
    for x, y in zip(_cdf_X[1:], _cdf_Y[1:]):
        pdf_X.append(x)
        pdf_Y.append(y - prev_y)
        prev_y = y
else:
    Tmin = int(10)           # minimum interarrival time, in seconds
    Tmax = int(12*3600)       # maximum interarrival time, in seconds


def exp_generator(exp_rate):
    while True:
        yield from np.random.exponential(1/exp_rate, size=(10**5,))


def generate_synt_traffic(N, exp_rate=0):
    """
    If `exp_rate` > 0, then the interarrival times follow an exponential distribution
    having as rate `exp_rate`
    """

    assert(P < Jmin)
    use_exp_delay = exp_rate > 0

    if use_exp_delay:
        # total delay of all the packets, in seconds
        exp_total_delay = 0
        # number of exponential arrival not used. An exponential arrival is not used
        # if it arrives before the original interarrival time of the packet
        exp_total_notused = 0

    cnt_datapckt = 0
    cnt_joins = 0

    packets_tot = []
    for dev_i in tqdm(range(N)):
        # generate random pattern for the current device
        pattern_len = randint(1, P)
        if USE_LOED_DISTR:
            pattern = choices(pdf_X, pdf_Y, k=pattern_len)
        else:
            pattern = [randint(Tmin, Tmax) for _ in range(pattern_len)]

        # generate first packet of the current device
        # let the first packet of a device be at a random time between 0 and a fraction of S
        first_packet_t = random() * 0.02 * S
        # use fake dev_address, it will be changed later
        next_packet = Packet(first_packet_t, str(dev_i), "---", None, None, -1, "Unconfirmed Uplink")
        
        # generate packets following the pattern up until S seconds
        packets_dev = []
        i_pattern = 0
        t = first_packet_t
        while t < S:
            packets_dev.append(next_packet)
            t_err = (1.0 if random()>0.5 else -1.0) * (random() * (Emax - Emin) + Emin)
            # It could be the case that t_err is negative and |t_err| > pattern[i_pattern].
            # In this case the following assert yields an error
            next_packet_t = t + pattern[i_pattern] + t_err
            if t_err < 0 and abs(t_err) > abs(pattern[i_pattern]):
                # next_packet_t is set to be 10 seconds after the previous one
                next_packet_t += abs(t_err) - abs(pattern[i_pattern]) + 10
            assert(next_packet_t > t)
            next_packet = Packet(next_packet_t, str(dev_i), "---", None, None, -1, "Unconfirmed Uplink")

            i_pattern = (i_pattern+1) % pattern_len
            t = next_packet_t

        # add join messages for the current device
        cnt_datapckt += len(packets_dev)
        joins_dev = []
        i = randint(Jmin, Jmax)
        while i < len(packets_dev)-1:
            t1 = packets_dev[i].t
            t2 = packets_dev[i+1].t
            assert(t2 > t1)
            join_msg_t = t1 + (random() * (t2-t1))
            assert(t1 < join_msg_t < t2)
            join_packet = Packet(join_msg_t, str(dev_i), "not_available", None, None, -1, "Join Request")
            joins_dev.append(join_packet)
            cnt_joins += 1
            i += randint(Jmin, Jmax)

        # merge packets with joins
        packets_dev += joins_dev
        # sort packets in time
        packets_dev.sort(key=lambda p: p.t)

        # if using a random exponential delay, delay the time of arrival of the 
        # generated packets such that the new interarrival times follow an exp. distr.
        if use_exp_delay:
            if show_plot:
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

            if show_plot:
                plt.figure(2)
                plt.title("Interarrival times - After exp delay")
                plt.hist([packets_dev[i].t-packets_dev[i-1].t for i in range(1, len(packets_dev))], bins=25)
                plt.show()

        # modify device addresses after a join
        dev_addr_curr = 0
        for packet in packets_dev:
            mtype = packet.mtype
            if mtype == "Unconfirmed Uplink":
                packet.dev_addr = str(dev_i) + "_" + str(dev_addr_curr)
            elif mtype == "Join Request":
                dev_addr_curr += 1
            else:
                raise Exception(f"bad mtype {mtype}")

        # add device packets to total packets
        packets_tot += packets_dev

    # sort all packets in time and write on disk
    packets_tot.sort(key=lambda p: p.t)
    pickle.dump(packets_tot, open("synth_traffic.pickle", "wb"))

    # print stats
    print(N, "total devices")
    print("Generated", cnt_datapckt, "data packets")
    print("Generated", cnt_joins, "join packets")
    print("Generated", cnt_datapckt+cnt_joins, "total packets")

    if use_exp_delay:
        print("--- Exponential delay stats:")
        print(f"---    Average packet delay per packet: {exp_total_delay/len(packets_tot):.2f} (s)")
        print("---    Average exponential arrival not used per packet:", exp_total_notused/len(packets_tot))
    else:
        print("--- Exponential delay not used")


if __name__ == "__main__":
    generate_synt_traffic(30, 0.03)
