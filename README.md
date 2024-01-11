# Compute Node

Compute node receives data from [Collector node(s)](https://github.com/D-A-I-S-I/compute-node) and runs chosen modules for different ml-models which classify data as malicious or benign.

## Dependencies

- [nats-py](https://pypi.org/project/nats-py/)
- [pyspark](https://pypi.org/project/pyspark/)
- [ijson](https://pypi.org/project/ijson/)
- [scapy](https://pypi.org/project/scapy/)
- [torch](https://pytorch.org/)
- [PyYAML](https://pypi.org/project/PyYAML/)
- [joblib](https://pypi.org/project/joblib/)
- [pandas](https://pandas.pydata.org/)
- [scikit-learn](https://scikit-learn.org/stable/)
- [matplotlib](https://matplotlib.org/)

AND

- [Docker](https://www.docker.com)
- [Docker Compose](https://github.com/docker/compose)
- [tshark](https://www.wireshark.org/docs/)

## Installation
Initializes VM, installs python reqs, starts NATS broker in Docker, then runs the main.py in compute node. dependencies are docker and docker Compose
```python
sudo make
```

## Usage

### Environment variables:


To set the URL to the NATS broker:

```shell
export BROKER_URL=<url>
```

To set the verbosity level of the programs output (defaults to INFO):

```shell
export LOG_LEVEL=<DEBUG|INFO|WARNING|ERROR|CRITICAL>
```

## Creating New Modules
New modules can created by inheriting from the `BaseModel` class. <!---The module will then need to be specified in the init file and -->Its dependencies should be added to the requirements.txt file.

## Module Configuration

Each module has a corresponding config file where one can edit the paths for the files/programs needed for that specific module. Different variables (such as alert_threshold) can also be changed`
