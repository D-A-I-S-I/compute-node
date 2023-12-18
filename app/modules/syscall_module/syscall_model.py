from base_model import BaseModel
from Autoencoder import Autoencoder
import torch

class SyscallModel(BaseModel):
    def __init__(self, model):
        super().__init__(model)

    @staticmethod
    def load_model(self, model_info: str, num_system_calls: int):
        """
        Initialize the model and load the model info.

        Args:
            model_info (str): 
            num_system_calls (int): number of system calls used in training
        """
        
        model_state = torch.load('trained_models/model_0.pth')
        model = Autoencoder(model_info['sequence_length'], num_system_calls, model_info['embedding_dim'], model_info['encoding_dim'], model_info['hidden_dim']) 
        model.load_state_dict(model_state)
        model.eval()
        return model