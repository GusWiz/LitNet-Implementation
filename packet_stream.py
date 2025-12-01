import pyshark
from queue import Queue
from threading import Event
from loguru import logger

"""This file handles the streaming of packets into a shared queue"""


def RunPacketStream(interface: str, packet_queue: Queue, stop_event: Event):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        logger.info(f"Starting live capture on interface: {interface}")
        for packet in capture.sniff_continuously():
            packet_queue.put(packet)
            if stop_event.is_set():
                logger.info("Stop event received, closing capture thread.")
                break
    
    except Exception as e:
        logger.exception(f"Packet capture error: {e}")
        exit

    logger.info("Packet_stream thread exiting gracefully")
