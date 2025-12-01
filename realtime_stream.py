from Litsune import Litsune
import numpy as np
import packet_stream as ps
from queue import Queue
import threading
import time
from iptables import block_ip, unblock_ip
from loguru import logger

##############################################################################
# Kitsune a lightweight online network intrusion detection system based on an ensemble of autoencoders (kitNET).
# For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection

# This script demonstrates Kitsune's ability to incrementally learn, and detect anomalies in recorded a pcap of the Mirai Malware.
# The demo involves an m-by-n dataset with n=115 dimensions (features), and m=100,000 observations.
# Each observation is a snapshot of the network's state in terms of incremental damped statistics (see the NDSS paper for more details)

#The runtimes presented in the paper, are based on the C++ implimentation (roughly 100x faster than the python implimentation)
###################  Last Tested with Anaconda 3.6.3   #######################

# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer
FMgrace = 5000 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 10000 #the number of instances used to train the anomaly detector (ensemble itself)

BLOCK_THRESHOLD = 50 #num of strikes before blocking
BLOCK_DURATION = 60 #duration to block IP in seconds

blocked_ips = set() #currently blocked IPs
unblock_schedule = {} #IP -> unblock time

# Build Litsune
logger.info("Initializing Litsune engine")
L = Litsune(max_autoencoder_size=maxAE,FM_grace_period=FMgrace,AD_grace_period=ADgrace)

capture_interface = input("Please input the interface to monitor traffic from: ")
logger.info(f"Starting capture on interface: {capture_interface}")

# Set up capture and begin listener thread
packet_queue = Queue(maxsize=capture_limit)
stop_event = threading.Event()
listener = threading.Thread(target=ps.RunPacketStream, args=(capture_limit, capture_interface, packet_queue, stop_event))
listener.start()

RMSEs = []
i = 0
start = time.time()
threshold = -1

# Set the threshold during the training phase
while i < ADgrace + FMgrace:
    packet = packet_queue.get()
    i += 1
    if i % 1000 == 0:
        logger.info(f"Training progress: {i}/{ADgrace + FMgrace}")
    L.curr_packet = packet
    rmse = L.proc_next_packet()
    if rmse > threshold:
        threshold = rmse
        logger.info(f"New maximum RMSE found. Updated threshold: {rmse}")
        
    if rmse == -1:
        continue
    RMSEs.append(rmse)

logger.info(f"The anomaly threshold has been successfully set at {threshold}")
logger.info("Beginning execution phase")


# Here we process (train/execute) each individual packet.
# In this way, each observation is discarded after performing process() method.
while True:
    packet = packet_queue.get()
    i+=1

    #unblock any IPs whose block duration has expired
    '''now = time.time()
    for ip in list(unblock_schedule.keys()):
        if now >= unblock_schedule[ip]:
            unblock_ip(ip)
            blocked_ips.remove(ip)
            del unblock_schedule[ip]'''

    if i % 1000 == 0:
       logger.info(f"Execution progress: {i}")
    L.curr_packet = packet
    rmse = L.proc_next_packet()
    if rmse == -1:
        continue
    if rmse > threshold:
        logger.warning(f"Anomalous packet detected: RMSE={rmse}")
        logger.warning(f"Packet details: {L.curr_packet}")
        L.update_anomList()
        #check count of anomalies for this source IP
        src_ip = L.currentSrc
        if L.anomList[src_ip] >= BLOCK_THRESHOLD:
            if src_ip not in blocked_ips:
                print(f"[ALERT] Source IP {src_ip} has reached {L.anomList[src_ip]} threshold.")
                block_ip(src_ip)
                blocked_ips.add(src_ip)
                unblock_schedule[src_ip] = time.time() + BLOCK_DURATION
                print(f"[BLOCKED] {src_ip} for 60 seconds")

    RMSEs.append(rmse)
    if (i > 25000):
        break
stop = time.time()
logger.info(f"Monitoring complete. Total runtime: {stop - start:.2f} seconds")

# Halt and join the listener thread
stop_event.set()
listener.join()

# Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
from scipy.stats import norm
benignSample = np.log(RMSEs[FMgrace+ADgrace+1:100000])
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

# plot the RMSE anomaly scores
logger.info("Plotting results")
from matplotlib import pyplot as plt
from matplotlib import cm
plt.figure(figsize=(10,5))
fig = plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
plt.yscale("log")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSE (log scaled)")
plt.xlabel("Time elapsed [min]")
figbar=plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.savefig("ExampleOutTest.png")
logger.info("Plot saved to ExampleOutTest.png")
logger.info("Program completed successfully.")