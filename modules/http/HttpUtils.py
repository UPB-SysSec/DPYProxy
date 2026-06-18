class HttpUtils:
    @staticmethod
    def insert(s: str, insertion: str, num: int, position: str, index: int = None) -> str:
        """
        Inserts a string into another string a specified number of times at a specified position.
        :param s: string to insert into
        :param insertion: string to insert
        :param num: number of times to insert
        :param position: position to insert at, either "start", "end", "middle", "random", or "index"
        :param index: index to insert at if position is
        :return: modified string
        """
        if position == "start":
            result = num * insertion + s
        if position == "end":
            result = s + num * insertion
        if position == "middle" or position == "random":
            index = len(s) // 2
            result = s[:index] + num * insertion + s[index:]
        if position == "index" and index is not None:
            result = s[:index] + num * insertion + s[index:]
        return result

    @staticmethod
    def replace(s: str, replacement: str, num: int, start_index: int, end_index: int) -> str:
        """
        Replaces a part of a string with another string a specified number of times.
        :param s: string to replace in
        :param replacement: string to replace with
        :param num: number of times to replace
        :param start_index: start index of part to replace
        :param end_index: end index of part to replace
        :return: modified string
        """
        return s[:start_index] + num * replacement + s[end_index:]

    @staticmethod
    def duplicate(s: str, start_index: int, end_index: int) -> str:
        """
        Duplicates a part of a string with another string a specified number of times.
        :param s: string to duplicate in
        :param start_index: start index of part to duplicate in
        :param end_index: end index of part to duplicate in
        :return: modified string
        """
        return 2 * s[start_index:end_index]

    @staticmethod
    def index_host_header(data_list: list[list[str]], number: int = 1) -> int:
        """
        Indexes all host headers.
        :param data_list: list of host headers
        :param number: number of host headers
        :return: indexed host headers
        """
        count = 0
        for i, line in enumerate(data_list):
            if "HOST" in line[0].upper():
                count += 1
                if count == number:
                    return i
        return -1

    @staticmethod
    def index_content_length_header(data_list: list[list[str]], number: int = 1) -> int:
        """
        Indexes all content length headers.
        :param data_list: list of content length headers
        :param number: number of content length headers
        :return: indexed content length headers
        """
        count = 0
        for i, line in enumerate(data_list):
            if "CONTENT-LENGTH" in line[0].upper():
                count += 1
                if count == number:
                    return i
        return -1

    @staticmethod
    def index_transfer_encoding_header(data_list: list[list[str]], number: int = 1) -> int:
        """
        Indexes all transfer encoding headers.
        :param data_list: list of transfer encoding headers
        :param number: number of transfer encoding headers
        :return: indexed transfer encoding headers
        """
        count = 0
        for i, line in enumerate(data_list):
            if "TRANSFER-ENCODING" in line[0].upper():
                count += 1
                if count == number:
                    return i
        return -1
