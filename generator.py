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

class Generator:

    S = 50*24*3600     # number of seconds to generate packets
    # Emin = 0.01            # minimum absolute error in the interarrival time, in seconds
    # Emax = 2           # maximum absolute error in the interarrival time, in seconds
    # P = 3              # maximum length of a pattern
    # Jmin = 10           # minimum number of messages before a join
    # Jmax = 300          # maximum number of messages before a join
    USE_LOED_DISTR = False       # use interarrival time distribution from LoED dataset
    Tmin = int(10)           # minimum interarrival time, in seconds
    Tmax = int(12*3600)       # maximum interarrival time, in seconds


    def __init__(self):
        pass
        #if self.USE_LOED_DISTR:
            # Data for interarrival distribution extracted from LoED dataset
        #    _cdf_X, _cdf_Y = pickle.load(open("LoED/interarrivals_X_cdf.pickle", "rb"))
        #    pdf_X, pdf_Y = [], []
        #    prev_y = _cdf_Y[0]
        #    for x, y in zip(_cdf_X[1:], _cdf_Y[1:]):
        #        pdf_X.append(x)
        #        pdf_Y.append(y - prev_y)
        #        prev_y = y


    def new_traffic_flow(self, N, P, Jmin, Jmax, Emin, Emax):
        #assert(P < self.Jmin)

        cnt_datapckt = 0
        cnt_joins = 0

        packets_tot = []
        for dev_i in tqdm(range(N)):
            # generate random pattern for the current device
            pattern_len = randint(1, P)
            if self.USE_LOED_DISTR:
                pattern = choices(self.pdf_X, self.pdf_Y, k=pattern_len)
            else:
                pattern = [randint(self.Tmin, self.Tmax) for _ in range(pattern_len)]

            # generate first packet of the current device
            # let the first packet of a device be at a random time between 0 and a fraction of S
            first_packet_t = random() * 0.02 * self.S
            # use fake dev_address, it will be changed later
            next_packet = Packet(first_packet_t, str(dev_i), "---", None, None, -1, "Unconfirmed Uplink")
            
            # generate packets following the pattern up until S seconds
            packets_dev = []
            i_pattern = 0
            t = first_packet_t
            while t < self.S:
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