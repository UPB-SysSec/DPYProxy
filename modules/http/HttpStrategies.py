from modules.http.HttpUtils import HttpUtils


class HttpStrategies:
    """
    Implements circumvention methods for HTTP-based censorship.
    Incorporates various basic manipulations of HTTP traffic to bypass censorship,
    as well as http request smuggling techniques.
    """

    @staticmethod
    def manipulations(data: bytes, strategy: int, http_smuggling_uncensored_url: str):
        data = data.decode("ASCII", errors="ignore")
        data_list = HttpStrategies.deconstruction(data)
        manipulation = HttpStrategies.switch_manipulation[strategy]

        if not HttpStrategies.strategy_is_valid(strategy):
            raise ValueError(f"Invalid http strategy {strategy}")

        if HttpStrategies.strategy_is_smuggling(strategy):
            data_list = HttpStrategies.prepare_request_for_smuggling(data_list, strategy, http_smuggling_uncensored_url)

        data_list = manipulation(data_list, strategy)
        data = HttpStrategies.reconstruction(data_list)
        data = data.encode("ASCII", errors="ignore")
        return data

    @staticmethod
    def prepare_request_for_smuggling(
        data_list: list[list[str]], smuggling: int, uncensored_domain: str
    ) -> list[list[str]]:

        request_line_01 = ["GET", " ", "/" + uncensored_domain.split("/", 3)[3], " ", "HTTP/1.1", "\x0d\x0a"]
        host_header_01 = ["Host:", " ", uncensored_domain.split("/", 3)[2], "\x0d\x0a"]
        request_line = data_list[0]
        host_header = data_list[HttpUtils.index_host_header(data_list, 1)]

        # constructing the headers
        content_length_header = ["Content-Length:", " ", "", "\x0d\x0a"]
        transfer_encoding_header = ["Transfer-Encoding:", " ", "chunked", "\x0d\x0a"]
        if smuggling <= 112 or (121 <= smuggling <= 128):  # CLTE
            content_length_header[2] = str(
                len("".join(request_line)) + len("".join(host_header)) + len("".join(["0", "\x0d\x0a", "\x0d\x0a"])) + 2
            )  # +2 for the \x0D\x0A after headers
        if (113 <= smuggling <= 120) or smuggling == 129:  # TECL
            content_length_header[2] = "0"

        # combining all parts of the smuggling request
        data_list = []
        data_list.append(request_line_01)
        data_list.append(host_header_01)
        data_list.append(content_length_header)
        data_list.append(transfer_encoding_header)
        data_list.append(["\x0d\x0a"])
        if smuggling <= 112 or (121 <= smuggling <= 128):  # CLTE
            data_list.append(["0", "\x0d\x0a", "\x0d\x0a"])
            data_list.append(request_line)
            data_list.append(host_header)
            data_list.append(["\x0d\x0a"])
        if (113 <= smuggling <= 120) or smuggling == 29:  # TECL
            data_list.append([format(len("".join(request_line)), "X"), "\x0d\x0a"])
            data_list.append(request_line)
            data_list.append(["\x0d\x0a"])
            data_list.append([format(len("".join(host_header)), "X"), "\x0d\x0a"])
            data_list.append(host_header)
            data_list.append(["\x0d\x0a"])
            data_list.append(["0", "\x0d\x0a", "\x0d\x0a"])
        return data_list

    @staticmethod
    def deconstruction(data: str) -> list[list[str]]:
        data_list = []
        parts = data.split("\x0d\x0a\x0d\x0a", 1)
        header_block = parts[0]
        body_block = parts[1] if len(parts) > 1 else ""
        for line in header_block.split("\x0d\x0a"):
            line_list = []
            element = ""
            for char in line:
                if char == " ":
                    if element:
                        line_list.append(element)
                        element = ""
                    line_list.append(" ")
                else:
                    element += char
            if element:
                line_list.append(element)
            line_list.append("\x0d\x0a")
            data_list.append(line_list)
        data_list.append(["\x0d\x0a"])
        data_list.append([body_block])
        return data_list

    @staticmethod
    def reconstruction(data_list: list[list[str]]) -> str:
        data = ""
        for line in data_list:
            for element in line:
                data += element
        return data

    # - - - - - - - - - - Specific Manipulations - - - - - - - - - - #

    @staticmethod  # for test purposes
    def no_manipulation(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        return data_list

    @staticmethod
    def altering_http_version(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 1:
            data_list[0][4] = HttpUtils.duplicate(data_list[0][4], 0, len(data_list[0][4]))
        if strategy == 2:
            data_list[0][4] = HttpUtils.replace(data_list[0][4], "OPTIONS", 1, 0, 8)
        return data_list

    @staticmethod
    def splitting_request_line(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 3:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x09", 14, "middle")
        if strategy == 4:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x09", 1434, "end")
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "1", 507, "start")
        if strategy == 5:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1, "end")
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "g", 1013, "end")
        return data_list

    @staticmethod
    def case_changes(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 6:
            data_list[HttpUtils.index_host_header(data_list, 1)] = [
                e.lower() for e in data_list[HttpUtils.index_host_header(data_list, 1)]
            ]
        if strategy == 7:
            data_list[HttpUtils.index_host_header(data_list, 1)] = [
                e.upper() for e in data_list[HttpUtils.index_host_header(data_list, 1)]
            ]
        return data_list

    @staticmethod
    def request_line_whitespaces(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 8:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x09", 1, "end")
        if strategy == 9:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x09", 1, "start")
        if strategy == 10:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x0a", 1, "start")
        if strategy == 11:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x0b", 1, "end")
        if strategy == 12:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x0d", 2, "end")
        if strategy == 13:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x09", 1, "end")
        if strategy == 14:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x09", 1, "start")
        if strategy == 15:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x0c", 1, "start")
        if strategy == 16:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x0d", 1, "start")
        if strategy == 17:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1, "end")
        if strategy == 18:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1, "start")
        if strategy == 19:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x0a\x09\x0a\x09", 1, "end")
        if strategy == 20:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x0a\x09", 1, "end")
        if strategy == 21:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x0a\x20\x0a\x20", 1, "end")
        if strategy == 22:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x20\x0a\x09", 1, "end")
        if strategy == 23:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x20", 1, "end")
        return data_list

    @staticmethod
    def host_header_whitespaces(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 24:
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x0a", 1, "end"
            )
        if strategy == 25:
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x0a", 1, "random"
            )
        if strategy == 26:
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x20\x0a", 1, "end"
            )
        if strategy == 27:
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x09", 1, "end"
            )
        if strategy == 28:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x09", 1, "end"
            )
        if strategy == 29:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x09", 1, "start"
            )
        if strategy == 30:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x0a\x0a", 1, "start"
            )
        if strategy == 31:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x0a ", 1, "start"
            )
        if strategy == 32:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x0a", 1, "end"
            )
        if strategy == 33:
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x20\x0a", 1, "start"
            )
        if strategy == 34:
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x20", 1, "end"
            )
        if strategy == 35:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x20", 1, "end"
            )
        if strategy == 36:
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][0], "\x20", 1, "start"
            )
        if strategy == 37:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x20", 2, "start"
            )
        return data_list

    @staticmethod
    def path_manipulation(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 38:
            data_list[0].insert(2, data_list[0][2])
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "3", 1004, "middle")
            data_list[0][3] = HttpUtils.replace(data_list[0][3], "&ultrasurf", 1, 0, len(data_list[0][3]))
        if strategy == 39:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x3f", 1, "start")
        return data_list

    @staticmethod
    def method_manipulation(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 40:
            data_list[0].insert(0, data_list[0][0])
        if strategy == 41:
            data_list[0][0] = HttpUtils.replace(data_list[0][0], "\x3a", 1, 0, len(data_list[0][0]))
        if strategy == 42:
            data_list[0][0] = HttpUtils.replace(data_list[0][0], "HTTP/1.1", 1, 0, len(data_list[0][0]))
        return data_list

    @staticmethod
    def host_header_shield(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 43:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1, "start")
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][2],
                "/?ultrasurf",
                1,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][2]),
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "/",
                64,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        if strategy == 44:
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "a",
                64,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        if strategy == 45:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x09", 1, "end")
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "a",
                64,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        if strategy == 46:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x0a", 1, "start")
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "\x2f",
                64,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        if strategy == 47:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x20", 1, "end")
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "\x2f",
                64,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        if strategy == 48:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x20", 1, "start")
            data_list.insert(
                HttpUtils.index_host_header(data_list, 1), data_list[HttpUtils.index_host_header(data_list, 1)][:]
            )
            data_list[HttpUtils.index_host_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_host_header(data_list, 1)][0],
                "\xc2\xb0",
                32,
                0,
                len(data_list[HttpUtils.index_host_header(data_list, 1)][0]),
            )
        return data_list

    @staticmethod
    def long_request(data_list: list[list[str]], strategy: int) -> list[list[str]]:
        if strategy == 49:
            data_list[0][2] = HttpUtils.replace(data_list[0][2], "/", 1434, 0, len(data_list[0][2]))
        if strategy == 50:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x20", 1413, "start"
            )
        if strategy == 51:
            data_list[HttpUtils.index_host_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_host_header(data_list, 1)][2], "\x20", 1434, "start"
            )
        if strategy == 52:
            data_list[0].insert(0, data_list[0][0])
            data_list[0][1] = HttpUtils.replace(data_list[0][1], "a", 1407, 0, len(data_list[0][1]))
        if strategy == 53:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x09", 2568, "end")
        if strategy == 54:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x0a", 4336, "start")
        if strategy == 55:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x20", 1413, "end")
        if strategy == 56:
            data_list[0][0] = HttpUtils.insert(data_list[0][0], "\x20", 1720, "end")
        if strategy == 57:
            data_list[0].insert(2, data_list[0][2])
            data_list[0][2] = HttpUtils.replace(data_list[0][2], "a", 1, 0, len(data_list[0][2]))
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "a", 1408, "start")
        if strategy == 58:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x0d", 1434, "end")
        if strategy == 59:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1413, "end")
        if strategy == 60:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x20", 1, "start")
            data_list[0][2] = HttpUtils.replace(data_list[0][2], "3", 511, 0, len(data_list[0][2]))
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "&", 1, "start")
        if strategy == 61:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x23", 1413, "end")
        if strategy == 62:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x23", 1, "end")
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\xc3", 470, "end")
        if strategy == 63:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x3f", 1413, "end")
        if strategy == 64:
            data_list[0][2] = HttpUtils.insert(data_list[0][2], "\x3f", 1413, "start")
        if strategy == 65:
            data_list[0][2] = HttpUtils.replace(data_list[0][2], "/", 1414, 0, len(data_list[0][2]))
        if strategy == 66:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x20", 1434, "end")
        if strategy == 67:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x20", 1434, "start")
        if strategy == 68:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\x25", 1434, "middle")
        if strategy == 69:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\xc2\x81", 773, "end")
        if strategy == 70:
            data_list[0][4] = HttpUtils.insert(data_list[0][4], "\xc3\x8b", 717, "middle")
        return data_list

    # - - - - - - - - - - HTTP Request Smuggling - - - - - - - - - - #

    @staticmethod
    def http_request_smuggling_CLTE_CL_manipulated(data_list: list[list[str]], smuggling: int) -> list[list[str]]:
        if smuggling == 101:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0], ":", 1, "end"
            )
        if smuggling == 102:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0], "\x20", 1, "index", index=-1
            )
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x20", 1, "end"
            )
        if smuggling == 103:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0], "\x09", 1, "index", index=-1
            )
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x09", 1, "end"
            )
        if smuggling == 104:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "'", 1, "start"
            )
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "'", 1, "end"
            )
        if smuggling == 105:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x20", 1, "start"
            )
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x20", 1, "end"
            )
        if smuggling == 106:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x20\x0aX: X", 1, "end"
            )
        if smuggling == 107:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\xc3\xbf\x0aX: X", 1, "end"
            )
        if smuggling == 108:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0], "\x0b", 1, "end"
            )
        if smuggling == 109:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x0a\x0aX: X", 1, "end"
            )
        if smuggling == 110:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\x0a", 1, "end"
            )
        if smuggling == 111:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0],
                "Content_Encoding:",
                1,
                0,
                len(data_list[HttpUtils.index_content_length_header(data_list, 1)][0]),
            )
        if smuggling == 112:
            data_list[HttpUtils.index_content_length_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][0], "\xc3\xbf", 1, "start"
            )
            data_list[HttpUtils.index_content_length_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_content_length_header(data_list, 1)][2], "\xc3\xbf", 1, "end"
            )
        return data_list

    @staticmethod
    def http_request_smuggling_TECL_TE_manipulated(data_list: list[list[str]], smuggling: int) -> list[list[str]]:
        if smuggling == 113:
            data_list.insert(
                HttpUtils.index_transfer_encoding_header(data_list, 1),
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][:],
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 2)][2] = HttpUtils.replace(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 2)][2],
                "identity\x0d\x0a",
                1,
                0,
                len(data_list[HttpUtils.index_transfer_encoding_header(data_list, 2)][2]),
            )
        if smuggling == 114:
            data_list.insert(
                HttpUtils.index_transfer_encoding_header(data_list, 1),
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][:],
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 2)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 2)][0], " ", 1, "start"
            )
        if smuggling == 115:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x20", 1, "start"
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x20", 1, "end"
            )
        if smuggling == 116:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x09", 1, "start"
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x09", 1, "end"
            )
        if smuggling == 117:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x0d", 1, "index", index=-1
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x0d", 1, "end"
            )
        if smuggling == 118:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0],
                "Content-Encoding:",
                1,
                0,
                len(data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0]),
            )
        if smuggling == 119:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\xc3\xbf", 1, "start"
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\xc3\xbf", 1, "end"
            )
        if smuggling == 120:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.replace(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0],
                "Transfer_Encoding:",
                1,
                0,
                len(data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0]),
            )
        return data_list

    @staticmethod
    def http_request_smuggling_CLTE_TE_manipulated(data_list: list[list[str]], smuggling: int) -> list[list[str]]:
        if smuggling == 121:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)] = [
                "TRANSFER-ENCODING:",
                " ",
                "CHUNKED",
                "\x0d\x0a",
            ]
        if smuggling == 122:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)] = [
                "TrAnSFer-EnCODinG:",
                " ",
                "cHuNkeD",
                "\x0d\x0a",
            ]
        if smuggling == 123:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], ":", 1, "end"
            )
        if smuggling == 124:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x20", 1, "index", index=-1
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x20", 1, "end"
            )
        if smuggling == 125:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x09", 1, "index", index=-1
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x09", 1, "end"
            )
        if smuggling == 126:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x0a", 1, "end"
            )
        if smuggling == 127:
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][0], "\x0a", 1, "start"
            )
            data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2] = HttpUtils.insert(
                data_list[HttpUtils.index_transfer_encoding_header(data_list, 1)][2], "\x0a", 1, "end"
            )
        return data_list

    @staticmethod
    def smuggling_with_no_manipulation(data_list: list[list[str]], smuggling: int) -> list[list[str]]:
        if smuggling == 128:
            return data_list
        if smuggling == 129:
            return data_list

    # http_request_smuggling_TECL_CL_manipulated not implemented, since the study showed no relevant techniques

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

    # description of technique after technique

    switch_manipulation = {
        ### BASIC MANIPULATIONS
        0: no_manipulation,  # no manipulation
        # - - - - - #
        1: altering_http_version,
        # HTTP:version  / duplicating version
        2: altering_http_version,
        # HTTP:version  / replacing HTTP/"..." with "OPTIONS"
        # - - - - - #
        3: splitting_request_line,
        # HTTP:version  / inserting 14*    "\x09"   in the middle  of value
        4: splitting_request_line,
        # HTTP:path     / inserting 1434*  "\x09"   at the end     of value
        # HTTP:path     / inserting 507*   "1"      at the start   of value
        5: splitting_request_line,
        # HTTP:path     / inserting 1*     "\x20"   at the end     of value
        # HTTP:path     / inserting 1013*  "g"      at the end     of value
        # - - - - - #
        6: case_changes,
        # HTTP:host     / line in lower case
        7: case_changes,
        # HTTP:host     / line in upper case
        # - - - - - #
        8: request_line_whitespaces,
        # HTTP:methode  / inserting 1*  "\x09"        at the end      of value
        9: request_line_whitespaces,
        # HTTP:methode  / inserting 1*  "\x09"        at the start    of value
        10: request_line_whitespaces,
        # HTTP:methode  / inserting 1*  "\x0A"        at the start    of value
        11: request_line_whitespaces,
        # HTTP:methode  / inserting 1*  "\x0B"        at the end      of value
        12: request_line_whitespaces,
        # HTTP:methode  / inserting 2*  "\x0D"        at the end      of value
        13: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x09"        at the end      of value
        14: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x09"        at the start    of value
        15: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x0C"        at the start    of value
        16: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x0D"        at the start    of value
        17: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x20"              at the end      of value
        18: request_line_whitespaces,
        # HTTP:path     / inserting 1*  "\x20"              at the start    of value
        19: request_line_whitespaces,
        # HTTP:version  / inserting 1*  "\x0A\x09\x0A\x09"  at the end      of value
        20: request_line_whitespaces,
        # HTTP:version  / inserting 1*  "\x0A\x09"          at the end      of value
        21: request_line_whitespaces,
        # HTTP:version  / inserting 1*  "\x0A\x20\x0A "     at the end      of value
        22: request_line_whitespaces,
        # HTTP:version  / inserting 1*  "\x20\x0A\x09"      at the end      of value
        23: request_line_whitespaces,
        # HTTP:version  / inserting 1*  "\x20"              at the end      of value
        # - - - - - #
        24: host_header_whitespaces,
        # HTTP:host     / duplicating:  inserting 1*    "\x0A"        at the end      of value
        # ,   second: nothing changed
        25: host_header_whitespaces,
        # HTTP:host     / duplicating:  inserting 1*    "\x0A"        at random       of name
        # ,    second: nothing changed
        26: host_header_whitespaces,
        # HTTP:host     / duplicating:  inserting 1*    "\x20\x0A"    at the end      of name
        # ,    second: nothing changed
        27: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x09"        at the end      of name
        28: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x09"        at the end      of value
        29: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x09"        at the start    of value
        30: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x0A\x0A"    at the start    of value
        31: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x0A "       at the start    of value
        32: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x0A"        at the end      of value
        33: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x20\x0A"    at the start    of name
        34: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x20"        at the end      of name
        35: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x20"        at the end      of value
        36: host_header_whitespaces,
        # HTTP:host     / inserting 1*  "\x20"        at the start    of name
        37: host_header_whitespaces,
        # HTTP:host     / inserting 2*  "\x20"        at the start    of value
        # - - - - - #
        38: path_manipulation,
        # HTTP:path     / duplicating:  inserting 1004* "3"     in the middle   of value
        # ,   second: replacing value with "&ultrasurf"
        39: path_manipulation,
        # HTTP:path     / inserting 1*  "\x3F"                  at the start    of value
        # - - - - - #
        40: method_manipulation,
        # HTTP:method   / duplicating: first nothing changed, second nothing changed
        41: method_manipulation,
        # HTTP:method   / replacing method with "\x3A"
        42: method_manipulation,
        # HTTP:method   / replacing method with "HTTP/1.1"
        # - - - - - #
        43: host_header_shield,
        # HTTP:path     / inserting 1*  "\x20"          at the start    of value
        # HTTP:host     / duplicating: replacing name with 64* "/" and replacing value with "/?ultrasurf"
        # , second: nothing changed
        44: host_header_shield,
        # HTTP:host     / duplicating: replacing name with 64* "a", second: nothing changed
        45: host_header_shield,
        # HTTP:method   / inserting 1*  "\x09"          at the end      of value
        # HTTP:host     / duplicating: replacing name with 64* "a", second: nothing changed
        46: host_header_shield,
        # HTTP:method   / inserting 1*  "\x0A"          at the start    of value
        # HTTP:host     / duplicating: replacing name with 64* "\x2F", second: nothing changed
        47: host_header_shield,
        # HTTP:method   / inserting 1*  "\x20"          at the end      of value
        # HTTP:host     / duplicating: replacing name with 64* "\x2F", second: nothing changed
        48: host_header_shield,
        # HTTP:path     / inserting 1*  "\x20"          at the start    of value
        # HTTP:host     / duplicating: replacing name with 32* "\xC2\xB0", second: nothing changed
        # - - - - - #
        49: long_request,
        # HTTP:path     / replacing value with 1434* "/"
        50: long_request,
        # HTTP:host     / inserting 1413*   "\x20"      at the start    of value
        51: long_request,
        # HTTP:host     / inserting 1434*   "\x20"      at the start    of value
        52: long_request,
        # HTTP:method   / duplicating: first nothing changed, second: replacing name with 1407* "a"
        53: long_request,
        # HTTP:method   / inserting 2568*   "\x09"      at the end      of value
        54: long_request,
        # HTTP:method   / inserting 4336*   "\x0A"      at the start    of value
        55: long_request,
        # HTTP:method   / inserting 1413*   "\x20"      at the end      of value
        56: long_request,
        # HTTP:method   / inserting 1720*   "\x20"      at the end      of value
        57: long_request,
        # HTTP:path     / duplicating: first: replacing value with 1* "a", second: nothing changed
        # HTTP:path     /               first: inserting 1408* "a" at the start of value
        58: long_request,
        # HTTP:path     / inserting 1434*   "\x0D"      at the end      of value
        59: long_request,
        # HTTP:path     / inserting 1413*   "\x20"      at the end      of value
        60: long_request,
        # HTTP:path     / inserting 1*      "\x20"      at the start    of value
        # HTTP:path     / replacing value with 511* "3"
        # HTTP:path     / inserting 1*      "&"         at the start    of value
        61: long_request,
        # HTTP:path     / inserting 1413*   "\x23"      at the end      of value
        62: long_request,
        # HTTP:path     / inserting 1*      "\x23"      at the end      of value
        # HTTP:path     / inserting 470*    "\xC3"      at the end      of value
        63: long_request,
        # HTTP:path     / inserting 1413*   "\x3F"      at the end      of value
        64: long_request,
        # HTTP:path     / inserting 1413*   "\x3F"      at the start    of value
        65: long_request,
        # HTTP:path     / replacing value with 1414* "/"
        66: long_request,
        # HTTP:version  / inserting 1434*   "\x20"      at the end      of value
        67: long_request,
        # HTTP:version  / inserting 1434*   "\x20"      at the start    of value
        68: long_request,
        # HTTP:version  / inserting 1434*   "\x25"      in the middle   of value
        69: long_request,
        # HTTP:version  / inserting 773*    "\xC2\x81"  at the end      of value
        70: long_request,
        # HTTP:version  / inserting 717*    "\xC3\x8B"  in the middle   of value
        ### SMUGGLING MANIPULATIONS
        101: http_request_smuggling_CLTE_CL_manipulated,
        # Double Colon:             Content-Length:: <len>
        102: http_request_smuggling_CLTE_CL_manipulated,
        # White-Space Injection:    Content-Length\x20: <len>\x20
        103: http_request_smuggling_CLTE_CL_manipulated,
        # White-Space Injection:    Content-Length\x09: <len>\x09
        104: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length: ’<len>’
        105: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length:\x20<len>\x20
        106: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length: <len>\x20\x0AX: X
        107: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length: <len>\xC3\xBF\x0AX: X
        108: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length:\x0B <len>
        109: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length: <len>\x0A\x0AX: X
        110: http_request_smuggling_CLTE_CL_manipulated,
        # Wrapping:                 Content-Length: <len>\x0A
        111: http_request_smuggling_CLTE_CL_manipulated,
        # Invalid Header:           Content-Encoding: <len>
        112: http_request_smuggling_CLTE_CL_manipulated,
        # Invalid Header:           \xC3\xBFContent-Length: <len>\xC3\xBF
        # - - - - - #
        113: http_request_smuggling_TECL_TE_manipulated,
        # Header manipulation:      Transfer-Encoding: identity\x0D\x0A
        114: http_request_smuggling_TECL_TE_manipulated,
        # Header manipulation:      Transfer-Encoding: chunked
        115: http_request_smuggling_TECL_TE_manipulated,
        # White-Space Injection:    \x20Transfer-Encoding: chunked\x20
        116: http_request_smuggling_TECL_TE_manipulated,
        # White-Space Injection:    \x09Transfer-Encoding: chunked\x09
        117: http_request_smuggling_TECL_TE_manipulated,
        # White-Space Injection:    Transfer-Encoding\x0D: chunked\x0D
        118: http_request_smuggling_TECL_TE_manipulated,
        # Invalid Header:           Content-Encoding: chunked
        119: http_request_smuggling_TECL_TE_manipulated,
        # Invalid Header:           \xC3\xBFTransfer-Encoding:chunked\xC3\xBF
        120: http_request_smuggling_TECL_TE_manipulated,
        # Invalid Header:           Transfer_Encoding: chunked
        # - - - - - #
        121: http_request_smuggling_CLTE_TE_manipulated,
        # Letter Case:              TRANSFER-ENCODING: CHUNKED
        122: http_request_smuggling_CLTE_TE_manipulated,
        # Letter Case:              TrAnSFer-EnCODinG: cHuNkeD
        123: http_request_smuggling_CLTE_TE_manipulated,
        # Double Colon:             Transfer-Encoding:: chunked
        124: http_request_smuggling_CLTE_TE_manipulated,
        # White-Space Injection:    Transfer-Encoding\x20: chunked\x20
        125: http_request_smuggling_CLTE_TE_manipulated,
        # White-Space Injection:    Transfer-Encoding\x09: chunked\x09
        126: http_request_smuggling_CLTE_TE_manipulated,
        # White-Space Injection:    Transfer-Encoding:\x0A chunked
        127: http_request_smuggling_CLTE_TE_manipulated,
        # White-Space Injection:    \x0ATransfer-Encoding: chunked\x0A
        # - - - - - #
        128: smuggling_with_no_manipulation,
        # CL/TE
        129: smuggling_with_no_manipulation,
        # TE/CL
    }

    @staticmethod
    def strategy_is_valid(strategy: int) -> bool:
        return HttpStrategies.strategy_is_basic(strategy) or HttpStrategies.strategy_is_smuggling(strategy)

    @staticmethod
    def strategy_is_basic(strategy: int) -> bool:
        return strategy in range(1, 71)

    @staticmethod
    def strategy_is_smuggling(strategy: int) -> bool:
        return strategy in range(101, 130)
