class DnsException(Exception):
    """
    For exceptions during the dns resolution
    """

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
