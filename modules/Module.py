from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace


class Module(ABC):
    """
    Abstract class for a module. A module abstracts certain proxy functionality such as TLS alterations or DNS
    alterations.
    They can be started and stopped independently.
    """

    def __init__(self, parser: ArgumentParser):
        self.parser = parser

    @abstractmethod
    def register_parameters(self):
        """
        Registers the module's CLI parameters.
        """
        pass

    @abstractmethod
    def extract_parameters(self, arguments: Namespace):
        """
        Extracts the module's registered CLI parameters from ArgumentParser's output.
        """

    @abstractmethod
    def start(self, ):
        """
        Starts the module. Without calling this function the module should not do anything. Should only be called after
        registering and extracting the module's CLI parameters.
        """
        pass


    @abstractmethod
    def stop(self):
        """
        Stops the module from accepting any future connections. Running connections are continued. Does nothing if the module has
        not been started before.
        """
        pass