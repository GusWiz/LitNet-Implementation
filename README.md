# Litsune: A Network Intrusion Protection System

This project is an extension and reworking of Kitsune (*Mirsky, Doitshman, Elovici and Shabtai*) 
by Andrew Lockett, Aaron Siemsen, Gustavo Hernandez, Aldo Guerrero, and Brian Lee.

Litsune is an AI-powered intrusion prevention system built on KitNET, a lightweight model designed
to run in realtime on limited hardware for enhanced network security,

Whereas its predecessor, Kitsune, was built primarily for offline detection through packet capture files of previous
traffic, Litsune is a "live" version of Kitsune that reads incoming traffic through pyshark, parses features of interest
from individual packets, then passes that information to KitNET's layer of autoencoders.

This can be seen in the following diagram:
![Concept](img/Litsune%20Concept.png)

## Dependencies
The necessary dependencies are listed in `requirements.txt`: use `pip install -r requirements.txt` to install all suitable versions.
Additionally, IPTables and tshark have to be installed and added to the system path.

## Running Litsune

To try running Litsune on your machine, you can use the provided example file, realtime_stream.py. Upon running 
realtime_stream.py you will be prompted for the name of the interface you would like to capture traffic from. 
With no changes to this the script, the model will be in training mode for the first 50,000 captured packets, then 
automatically end the capture after 100,000 packets. When capture ceases, there will be an output graph of the anomaly
scores saved as ExampleOutTest.png 

*Example* 

`python realtime_stream.py`
