class ParserException(Exception):
    """
    For exceptions during the parsing process
    """

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
