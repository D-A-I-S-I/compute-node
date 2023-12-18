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
    def preprocess_input(self, input_data):
        """
        Preprocess input data before feeding it to the model.
        """
        pass

    @abstractmethod
    def classify(self, preprocessed_data):
        """
        Perform classification on the preprocessed data.
        """
        pass

    @abstractmethod
    def log_classification(self, classification_result):
        """
        Log the classification result.
        """
        pass

    @abstractmethod
    def calculate_classification_rate(self, classification_results):
        """
        Calculate and return the classification rate based on the given results.
        """
        pass