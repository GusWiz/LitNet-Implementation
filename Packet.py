class Packet:
    """
    Class 
    """
    def __init__(self, packet):
        """
        Constructor for Packet object.
        Args:
            source (str): ip address of source of malicous packet
            arg2 (str): ...
            year (int): 
            color (str): 
        """
        self.packet = packet
        self.anomalyCount = 0

        self.source = packet.ip # idk how to get packet ip rn 

    
        def anomolyDetected(): 
            self.Anomalycount += 1
        

    