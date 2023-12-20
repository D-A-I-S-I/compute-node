#TODO How/Where to loop until buffer is full

from ..base_model import BaseModel
import subprocess
from joblib import load
import pandas as pd
import numpy as np
import json
import asyncio

class NetworkModel(BaseModel):
    def __init__(self):
        super().__init__()
        self.buffer = []
        #TODO ABSTRACT TO CONFIG FILE
        self.pcap_path = "/FlowMeter/pkg/packets/merged_pcap"
        self.csv_path = "/FlowMeter/pkg/flowOutput/merged_pcap_flow_stats"
        self.model = self.load_model()


    async def run(self):
        while(True):
            filledBuffer = False
            while not filledBuffer:
                filledBuffer = self.read_from_buffer()
                await asyncio.sleep(0.1)
            
            self.preprocess_input()
            self.classify()
            self.log_classification()
            await asyncio.sleep(0)
        
    def load_model(self):
        """
        Load the model.
        """
        model = load('trained_model/network_model.joblib')
        return model


    def write_to_buffer(self, data):
        """
        Write data to buffer.
        """
        self.buffer.append(data)


    def read_from_buffer(self):
        """
        Append receieved to buffer and check size of buffer.
        """
        if len(self.buffer) < 10:
            return False
        
        elif len(self.buffer) > 10:
            self.buffer.pop()
            return True
        
        else:
            return True


    def preprocess_input(self):
        """
        Preprocess input data before feeding it to the model.
        """

        mergecap_cmd = ["mergecap", "-w", self.pcap_path] + self.buffer[:10]

        try:
            # Run mergecap_cmd
            subprocess.run(mergecap_cmd, check=True)
            print(f"Merged capture files into {self.pcap_path}")
        
        except subprocess.CalledProcessError as e:
            print(f"Error while merging capture files: {e}")
            exit
        
        #TODO ABSTRACT THIS TO CONFIG FILE
        flow_cmd = [".FlowMeter/pkg/flowmeter -ifLiveCapture=false -fname=merged_pcap -maxNumPackets=40000000 -ifLocalIPKnown false"]

        try:
            # Run flow_cmd
            subprocess.run(flow_cmd, check=True)
            print(f"Transformed PCAP into CSV: {self.csv_path}")
        
        except subprocess.CalledProcessError as e:
            print(f"Error while converting to flow data: {e}")
            exit
        
        #Pre-process CSV file
        columns = json.load('data_features.json')
        colsPerTime = columns['colsPerTime']
        feature_cols = columns['feature_cols']
        data = pd.read_csv(self.csv_path, delimiter=",")

        for feature in colsPerTime:
            data[feature + "PerTime"] = data[feature] / data["flowDuration"]
        data = data[feature_cols]

        data.to_csv("/FlowMeter/pkg/flowOutput/merged_pcap_flow_stats", index=False)


    def classify(self):
        """
        Perform classification on the preprocessed data.
        """
        data = pd.read_csv(self.csv_path, delimiter=",")
        predictions = self.model.predict(data)


        target_class = 1 #1 == Benign
        percentage = np.mean(predictions == target_class) * 100
        print(f"Percentage of class {target_class}: {percentage:.2f}%")
        pass


    def log_classification(self, classification_result):
        """
        Log the classification result.
        """

        pass




