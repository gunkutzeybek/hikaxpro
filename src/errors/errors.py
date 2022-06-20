class IncorrectResponseContentError(Exception):
    def __init__(self):
        super().__init__("Response content is not in expected form.")    

class UnexpectedResponseCodeError(Exception):
    def __init__(self, responseCode, responseText):
        super().__init__(f"Unexpected response status code {responseCode} returned with message {responseText}")