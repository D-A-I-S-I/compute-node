from abc import ABC, abstractmethod

class BaseModel(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def run(self):
        """
        Run the model. Read, Classify, Log, Repeat.
        """
        pass

    @abstractmethod 
    def load_model(self):
        """
        Load the model.
        Child class should have @staticmethod on this.
        """
        pass

    @abstractmethod
    def preprocess_input(self):
        """
        Preprocess input data before feeding it to the model.
        """
        pass

    @abstractmethod
    def classify(self):
        """
        Perform classification on the preprocessed data.
        """
        pass

    @abstractmethod
    def log_classification(self):
        """
        Log the classification result.
        """
        pass

    @abstractmethod
    def write_to_buffer(self, data):
        """
        Write data to buffer.
        """
        pass

    @abstractmethod
    def read_from_buffer(self):
        """
        Read data from the file.
        """
        pass