from Autoencoder import Autoencoder
from ..base_model import BaseModel
from pathlib import Path

import logging
import asyncio
import torch
import json
import yaml
import time
import csv

class SyscallModel(BaseModel):
    def __init__(self):
        super().__init__()
        script_dir = Path(__file__).parent.absolute()

        with open(script_dir / 'syscall.conf') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
            
        self.model = self.load_model(script_dir / config['paths']['model_path'], 
                                     script_dir / config['paths']['model_info_path'], 
                                     config['general']['num_system_calls'])
        
        self.syscall_mapping = {i: i for i in range(config['general']['num_system_calls'])}
        self.sequence_length = self.model.sequence_length
        self.batch_size = config['general']['batch_size']
        self.threshold = config['general']['threshold']
        self.read_size = config['general']['read_size']
        self.last_read_position = 0
        self.buffer = []

    async def run(self):
        """
        Run the model. 
        Read, Classify, Log, Repeat.
        """
        while True:
            batch = []
            while len(self.buffer) < self.batch_size:
                batch = self.read_from_buffer()
                await asyncio.sleep(0.1) # FIXME adjust the sleep time as needed.

            # Preprocess the data
            preprocessed_batch = self.preprocess_input(batch)

            # Classify the data
            start_time = time.time()
            classifications, losses = self.classify(preprocessed_batch)
            end_time = time.time()

            # Log the classification results
            self.log_classification(losses, classifications, start_time, end_time)

    def load_model(self, model_path: str, model_info_path: str, num_system_calls: int):
        """
        Initialize the model and load the model info.
        Call this before creating class instance.

        Args:
            model_path (str): model file path (contains model weights)
            model_info (str): model info file path (contains model metadata)
            num_system_calls (int): number of system calls used in training
        """

        with open(model_info_path, 'r') as f:
            model_info = json.load(f)

        model_state = torch.load(model_path)
        model = Autoencoder(model_info['sequence_length'],
                            num_system_calls, 
                            model_info['embedding_dim'],
                            model_info['encoding_dim'],
                            model_info['hidden_dim']) 
        model.load_state_dict(model_state)
        model.eval()
        return model
    
    def preprocess_sequence(self, sequence):
        """
        Preprocess a single sequence of system calls using the provided mapping.

        Args:
            sequence (list): list of system calls
        """
        mapping = self.syscall_mapping
        sequence_length = self.sequence_length

        # Map the system calls to indices and pad/truncate the sequence
        mapped_sequence = [mapping.get(int(call), 0) for call in sequence]
        if len(mapped_sequence) < sequence_length: mapped_sequence += [0] * (sequence_length - len(mapped_sequence))
        else: mapped_sequence = mapped_sequence[:sequence_length]

        return torch.tensor(mapped_sequence, dtype=torch.long).unsqueeze(0)
    
    def preprocess_input(self, batch):
        """
        Preprocess input data before feeding it to the model.

        Args:
            batch (list): list of system call sequences
        """
        tensor_batch = torch.stack(batch)
        return self.model.embedding(tensor_batch).view(tensor_batch.size(0), -1)
    
    def read_from_buffer(self):
        """
        Reads a batch of syscalls from the buffer, creates sequences, and slides the batch window over the buffer. 
        Returns the created sequences.
        """
        batch_syscalls = self.buffer[:self.batch_size]
        batch_sequences = [batch_syscalls[i:i + self.sequence_length] for i in range(0, len(batch_syscalls), self.sequence_length)]
        
        # Slide the batch window over the buffer by a length of `stride` syscall(s).
        # This creates a rolling window of syscall sequences that are processed as a batch.
        stride = 1
        self.buffer = self.buffer[stride:] # * Stride may need to be increased

        return batch_sequences

    def write_to_buffer(self, data: str):
        """
        Write data to buffer.

        Args:
            data (str): data to be written to buffer
        """
        if data is not None:
            self.buffer.append(data.split())
        else:
            logging.error("Syscall Module: Received empty data.")

    def classify(self, preprocessed_batch):
        """
        Classify the preprocessed data.
        """
        # Classify the data
        with torch.no_grad():
            outputs = self.model(preprocessed_batch).view(preprocessed_batch.size(0), -1)

        # Compute loss
        criterion = torch.nn.MSELoss(reduction='none')
        losses = criterion(outputs, preprocessed_batch).mean(dim=1)

        # Classify the sequences
        classifications = self.classify(losses)
        classifications = ['POSSIBLE INTRUSION' if loss > self.threshold else 'Normal' for loss in losses]

        return classifications, losses

    def log_classification(self, losses: list, classifications: list, start_time: float, end_time: float):
        """
        Compute logging info.

        Args:
            losses (list): list of losses
            classifications (list): list of classifications
            start_time (float): start time of the batch
            end_time (float): end time of the batch
        """
        num_sequences = len(self.buffer[:self.batch_size])
        time_taken = end_time - start_time
        sequences_per_second = num_sequences / time_taken

        # Compute average loss factors for normal and intrusion sequences
        normal_losses = [loss.item() / self.threshold for loss, classification in zip(losses, classifications) if classification == 'Normal']
        intrusion_losses = [loss.item() / self.threshold for loss, classification in zip(losses, classifications) if classification == 'POSSIBLE INTRUSION']
        percentage_intrusions = len(intrusion_losses) / len(losses) * 100

        average_normal_loss_factor = sum(normal_losses) / len(normal_losses) if normal_losses else 0
        average_intrusion_loss_factor = sum(intrusion_losses) / len(intrusion_losses) if intrusion_losses else 0

        # Write the logging info to the CSV file
        with open('syscall_logs.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([end_time, sequences_per_second, self.batch_size,
                             average_normal_loss_factor, average_intrusion_loss_factor,
                             self.threshold, percentage_intrusions])
            
        logging.log(logging.INFO, f"Syscall Module: {num_sequences} sequences classified in {time_taken} seconds. \
                    ({sequences_per_second} sequences per second)")
