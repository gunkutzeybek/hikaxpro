class SessionLogin:
    def __init__(self, sessionID, userName, password):
        self.sessionID = sessionID
        self.password = password
        self.userName = userName
        self.sessionIDVersion = "2.1"