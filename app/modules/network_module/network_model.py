#TODO How/Where to loop until buffer is full

from ..base_model import BaseModel
import subprocess
from joblib import load
import pandas as pd
import numpy as np
import json
import asyncio
from pathlib import Path
import time
import csv
import os
import logging
import yaml

class NetworkModel(BaseModel):
    module_name = "network_traffic"
    def __init__(self):
        super().__init__()
        self.buffer = []
        self.script_dir = Path(__file__).parent.absolute()

        with open(self.script_dir / 'network.conf') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        self.pcap_path = self.script_dir / config['paths']['pcap_path']
        self.csv_path = self.script_dir / config['paths']['csv_path']
        self.json_path = self.script_dir / config['paths']['json_path']
        self.model_path = self.script_dir / config['paths']['model_path']
        self.flowmeter_path = self.script_dir / config['paths']['flowmeter_path']
        self.model = self.load_model()


    async def run(self):
        print("Network Module: Running")
        while(True):
            filledBuffer = False
            while not filledBuffer:
                filledBuffer = self.read_from_buffer()
                await asyncio.sleep(0.1)
            
            self.preprocess_input()
            start_time = time.time()
            percentage = self.classify()
            end_time= time.time()
            self.log_classification(start_time, end_time, percentage)
            await asyncio.sleep(0)
        
    def load_model(self):
        """
        Load the model.
        """
        model = load(self.script_dir / self.model_path)
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
        if len(self.buffer) < 150:
            return False
        
        elif len(self.buffer) > 150:
            self.buffer.pop()
            return True
        
        else:
            return True


    def preprocess_input(self):
        """
        Preprocess input data before feeding it to the model.
        """
        #Merge json files and convert to pcap
        merged_json = {}
        for i in range(150):
            json_file = json.load(self.buffer[i])
            merged_json.update(json_file)

        json.dump(merged_json, self.json_path)
        
        jsonToPcap_cmd = ["python3", self.script_dir / "json2pcap.py", "-i", self.json_path, "-o", self.pcap_path]

        try:
            subprocess.run(jsonToPcap_cmd)
        
        except:
            print(f"Error while converting json to pcap: {e}")
            exit

        ######DO NOT USE THIS########
        # mergecap_cmd = ["mergecap", "-w", self.pcap_path] + self.buffer[:150]
        # try:
        #     # Run mergecap_cmd
        #     subprocess.run(mergecap_cmd, check=True)
        #     print(f"Merged capture files into {self.pcap_path}")
        
        # except subprocess.CalledProcessError as e:
        #     print(f"Error while merging capture files: {e}")
        #     exit
        ##############################

        flow_cmd = [self.script_dir / self.flowmeter_path, "-ifLiveCapture=false", "-fname=merged_pcap", "-maxNumPackets=40000000", "-ifLocalIPKnown", "false"]

        try:
            # Run flow_cmd
            subprocess.run(flow_cmd, check=True)
            print(f"Transformed PCAP into CSV: {self.csv_path}")
        
        except subprocess.CalledProcessError as e:
            print(f"Error while converting to flow data: {e}")
            exit
        
        #Pre-process CSV file
        columns = json.load(self.script_dir / 'data_features.json')
        colsPerTime = columns['colsPerTime']
        feature_cols = columns['feature_cols']
        data = pd.read_csv(self.csv_path, delimiter=",")

        for feature in colsPerTime:
            data[feature + "PerTime"] = data[feature] / data["flowDuration"]
        data = data[feature_cols]

        data.to_csv(self.script_dir / self.csv_path, index=False)


    def classify(self):
        """
        Perform classification on the preprocessed data.
        """
        data = pd.read_csv(self.csv_path, delimiter=",")
        predictions = self.model.predict(data)


        target_class = 1 #1 == Benign
        percentage = np.mean(predictions == target_class) * 100
        print(f"Percentage of class {target_class}: {percentage:.2f}%")
        return percentage
        


    def log_classification(self, start_time, end_time, percentage):
        """
        Log the classification result.
        """
        total_time = end_time - start_time
        #Check if csv exists
        if not os.path.exists('network_logs.csv'):
            op = 'w'
        else:
            op = 'a'
        # Write the logging info to the CSV file
        with open('network_logs.csv', op, newline='') as f:
            writer = csv.writer(f)
            writer.writerow([total_time, end_time, percentage])
        logging.log(logging.INFO, f"Network Module: Total classification time was {total_time}. Percentage of flows classfied as benign was {percentage}")
        




