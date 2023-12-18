#TODO How/Where to loop until buffer is full

from base_model import BaseModel
import os
import subprocess

class SyscallModel(BaseModel):
    def __init__(self):
        super().__init__()
        self.buffer = []
        self.pcap_path = "PATH TO PCAP FILE (/FlowMeter/pkg/packets/FILENAME)"
        self.csv_path = "PATH TO CSV FILE  (/FlowMeter/pkg/flowOutput/FILENAME)"
        self.model = self.load_model(self)


    def load_model(self):
        """
        Load the model.
        """
        pass


    def receive_input(self, outfile):
        """
        Append receieved to buffer and check size of buffer.
        """
        #TODO check how to store json files in buffer
        self.buffer.append(outfile)

        if len(self.buffer) < 10:
            return False
        
        elif len(self.buffer) > 10:
            self.buffer.pop
            return True
        
        else:
            return True


    def preprocess_input(self, json):
        """
        Preprocess input data before feeding it to the model.
        """

        mergecap_cmd = ["mergecap", "-w", self.pcap_path] + self.buffer

        try:
            # Run mergecap_cmd
            subprocess.run(mergecap_cmd, check=True)
            print(f"Merged capture files into {self.pcap_path}")
        
        except subprocess.CalledProcessError as e:
            print(f"Error while merging capture files: {e}")
            exit
        
        flow_cmd = [".PATH_TO_FLOWMETER/flowmeter -ifLiveCapture=false -fname=merged_pcap -maxNumPackets=40000000 -ifLocalIPKnown false"]

        try:
            # Run flow_cmd
            subprocess.run(flow_cmd, check=True)
            print(f"Transformed PCAP into CSV: {self.csv_path}")
        
        except subprocess.CalledProcessError as e:
            print(f"Error while converting to flow data: {e}")
            exit




    def classify(self, preprocessed_data):
        """
        Perform classification on the preprocessed data.
        """
        pass


    def log_classification(self, classification_result):
        """
        Log the classification result.
        """
        pass


    def calculate_classification_rate(self, classification_results):
        """
        Calculate and return the classification rate based on the given results.
        """
        pass



