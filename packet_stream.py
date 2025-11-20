import pyshark
from queue import Queue
from threading import Event

"""This file handles the streaming of packets into a shared queue"""


def RunPacketStream(interface: str, packet_queue: Queue, stop_event: Event):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            packet_queue.put(packet)
            if stop_event.is_set():
                break
    
    except Exception as e:
        print(f"Could not begin packet capture: {e}")
        exit

    print("Packet_stream thread exiting gracefully")
