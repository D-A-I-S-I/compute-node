from Autoencoder import Autoencoder
from base_model import BaseModel

import torch
import json
import yaml

class SyscallModel(BaseModel):
    def __init__(self):
        super().__init__()
        with open('syscall.conf') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        
        self.model = self.load_model(config['paths']['model_path'], config['paths']['model_info_path'], config['general']['num_system_calls'])
        self.syscall_mapping = {i: i for i in range(config['general']['num_system_calls'])}
        self.sequence_length = self.model.sequence_length
        self.threshold = config['general']['threshold']
        self.read_size = config['general']['read_size']
        self.batch_size = config['general']['batch_size']
        self.last_read_position = 0
        self.buffer = []

    def run(self):
        """
        Run the model. Read, Classify, Log, Repeat.
        """
        pass

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
    
    def preprocess_input(self, sequence):
        """
        Preprocess a single sequence of system calls using the provided mapping.

        Args:
            sequence (list): list of system calls
        """
        mapping = self.syscall_mapping
        sequence_length = self.sequence_length

        # Map the system calls to indices and pad/truncate the sequence
        mapped_sequence = [mapping.get(int(call), 0) for call in sequence]

        if len(mapped_sequence) < sequence_length:
            mapped_sequence += [0] * (sequence_length - len(mapped_sequence))
        else:
            mapped_sequence = mapped_sequence[:sequence_length]

        return torch.tensor(mapped_sequence, dtype=torch.long).unsqueeze(0)
    
    def read_data(self):
        """
        Collect data.
        """
        pass

    def compute_logging_info(self, losses, classifications, start_time, end_time):
        """
        Compute logging info.
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

        return sequences_per_second, average_normal_loss_factor, average_intrusion_loss_factor, percentage_intrusions